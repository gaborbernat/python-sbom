"""Load content providers and identify their project-local source files."""

from __future__ import annotations

__lazy_modules__ = [
    "copy",
    "importlib.machinery",
    "importlib.metadata",
    "inspect",
    "pathlib",
    "pkgutil",
    "python_sbom",
    "python_sbom._model._bom",
]

import inspect
import pkgutil
import sys
from contextlib import contextmanager
from copy import copy
from importlib.machinery import PathFinder
from importlib.metadata import entry_points
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Final

from python_sbom import SbomError
from python_sbom._model._bom import (  # simplint: ignore[private-import-path]  # avoid root export
    checked_contributions,
)
from python_sbom._model._content import (  # simplint: ignore[private-import-path]  # avoid root export
    BundledWheelInfo,
    ContentProvider,
    Contributions,
)

if TYPE_CHECKING:
    from collections.abc import Generator
    from importlib.metadata import EntryPoint

    from python_sbom import ProviderContext
    from python_sbom._model._inputs import Settings  # simplint: ignore[private-import-path]  # avoid root export


def resolve_provider(
    given: ContentProvider | str | None, settings: Settings, root: Path
) -> tuple[ContentProvider, tuple[PurePosixPath, ...]]:
    spec = settings.content_provider if given is None else given
    if isinstance(spec, ContentProvider):
        provider = spec
    elif isinstance(spec, str):
        provider = _load(spec, root)
    elif spec:
        provider = _Providers(tuple(_load(name, root) for name in spec))
    else:
        provider = ContentProvider()
    members = provider.members if isinstance(provider, _Providers) else (provider,)
    scripts: dict[PurePosixPath, None] = {}
    for member in members:
        scripts.update(dict.fromkeys(_provider_scripts(member, root)))
    return provider, tuple(scripts)


def _load(spec: str, root: Path) -> ContentProvider:
    if ":" in spec:
        with _project_imports(spec, root):
            try:
                provider = pkgutil.resolve_name(spec)
            except (ImportError, AttributeError, ValueError) as error:
                msg = f"content provider {spec!r} does not load from {root}: {error}"
                raise SbomError(msg) from error
    else:
        entry = _entry_point(spec)
        try:
            provider = entry.load()
        except (ImportError, AttributeError, ValueError) as error:
            msg = f"content provider {spec!r} does not load from entry point {entry.value!r}: {error}"
            raise SbomError(msg) from error
    if isinstance(provider, type) and issubclass(provider, ContentProvider):
        provider = provider()
    if not isinstance(provider, ContentProvider):
        msg = f"content provider {spec!r} is not a ContentProvider subclass or instance"
        raise SbomError(msg)
    return provider


@contextmanager
def _project_imports(spec: str, root: Path) -> Generator[None, None, None]:
    # resolve_name also takes a bare module, which is no provider
    module_name, _, attribute = spec.partition(":")
    if not (module_name and attribute):
        msg = f"content provider {spec!r} must be `module:attribute`"
        raise SbomError(msg)
    # the import cache is per process, so a hatch build of a second project, or a test suite building copies of one,
    # would get the provider module the first project imported; the outermost module the project provides that the
    # cache holds from elsewhere is dropped with its submodules, so the project's own copy loads, while a provider built
    # earlier keeps the module objects it already references
    if (other := _imported_elsewhere(module_name, root)) is not None:
        for cached in [name for name in sys.modules if name == other or name.startswith(f"{other}.")]:
            del sys.modules[cached]
    sys.path.insert(0, str(root))
    try:
        yield
    finally:
        sys.path.remove(str(root))


def _imported_elsewhere(module_name: str, root: Path) -> str | None:
    # each package on the way down to the module, and the module itself, that the project provides is compared with what
    # is already imported under its name; namespace packages merge, so only modules and regular packages can clash
    search: list[str] | None = [str(root)]
    parts: Final[list[str]] = module_name.split(".")
    for depth in range(1, len(parts) + 1):
        if search is None or (found := PathFinder.find_spec(".".join(parts[:depth]), search)) is None:
            return None
        imported = getattr(sys.modules.get(found.name), "__file__", None)
        if (
            found.origin is not None
            and imported is not None
            and Path(imported).resolve() != Path(found.origin).resolve()
        ):
            return found.name
        search = None if found.submodule_search_locations is None else list(found.submodule_search_locations)
    return None


def _entry_point(name: str) -> EntryPoint:
    group = "python_sbom.content_provider.v0"
    matches = entry_points(group=group, name=name)
    if not matches:
        msg = f"no content provider named {name!r} is installed in entry point group {group!r}"
        raise SbomError(msg)
    if len(matches) > 1:
        targets = ", ".join(sorted(entry.value for entry in matches))
        msg = f"multiple content providers named {name!r} in entry point group {group!r}: {targets}"
        raise SbomError(msg)
    (entry,) = matches
    return entry


class _Providers(ContentProvider):
    def __init__(self, members: tuple[ContentProvider, ...]) -> None:
        self.members = members

    def bundled_wheel(self, context: ProviderContext, wheel: PurePosixPath) -> BundledWheelInfo:
        context = copy(context)
        combined = BundledWheelInfo()
        for member in self.members:
            context.previous_bundled_wheel = combined
            info = member.bundled_wheel(context, wheel)
            combined.properties.extend(info.properties)
            if info.supplier is not None:
                combined = BundledWheelInfo(properties=combined.properties, supplier=info.supplier)
        return combined

    def contributions(self, context: ProviderContext) -> Contributions:
        context = copy(context)
        combined = Contributions()
        context.previous_contributions = combined
        for member in self.members:
            added = checked_contributions(member.contributions(context), member)
            combined.components.extend(added.components)
            combined.dependencies.extend(added.dependencies)
            combined.root_properties.extend(added.root_properties)
            combined.tools.extend(added.tools)
        return combined


def _provider_scripts(provider: ContentProvider, root: Path) -> tuple[PurePosixPath, ...]:
    # each class of the provider defined in the project shapes the document, a base class or mixin as much as the class
    # itself, so the SBOM lists their modules among the build tools; python-sbom's own ContentProvider adds nothing
    found: Final[dict[PurePosixPath, None]] = {}
    for cls in type(provider).__mro__:
        if cls in {ContentProvider, object}:
            continue
        if (source := _source(cls)) is None:
            continue
        resolved, base = Path(source).resolve(), root.resolve()
        if resolved.is_relative_to(base):
            found[PurePosixPath(resolved.relative_to(base).as_posix())] = None
    return tuple(found)


def _source(cls: type) -> str | None:
    # a method's code names the file even for a module hatchling loaded outside the import system, such as a custom
    # hook script
    methods = (
        function.__code__.co_filename
        for _, function in inspect.getmembers(cls, inspect.isfunction)
        if function.__qualname__.startswith(f"{cls.__qualname__}.")
    )
    return next(methods, getattr(sys.modules.get(cls.__module__), "__file__", None))


__all__ = [
    "resolve_provider",
]
