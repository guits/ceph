import sys
from pathlib import Path

from ceph.cephadm.images import DefaultImages
from cephadmlib.constants import DEFAULT_IMAGE, DEFAULT_REGISTRY

EXPECTED_COUNTS = {
    'docker.io': 4,
    'quay.io': 16,
    'quay.ceph.io': 0,
}


def images_py_path() -> Path:
    return (
        Path(__file__).resolve().parents[2]
        / 'python-common'
        / 'ceph'
        / 'cephadm'
        / 'images.py'
    )


def registry_host(image_ref: str) -> str:
    return image_ref.split('/', 1)[0]


def count_lines(path: Path, text: str) -> int:
    return sum(text in line for line in path.read_text().splitlines())


def main() -> int:
    refs = [image.image_ref for image in DefaultImages]
    refs.extend((DEFAULT_IMAGE, DEFAULT_REGISTRY))
    unknown = sorted({
        registry_host(ref)
        for ref in refs
        if registry_host(ref) not in EXPECTED_COUNTS
    })
    failed = False
    if unknown:
        allowed = ', '.join(EXPECTED_COUNTS)
        print(
            f'registries not in allowlist ({allowed}): {", ".join(unknown)}',
            file=sys.stderr,
        )
        failed = True

    images_py = images_py_path()
    for registry, want in EXPECTED_COUNTS.items():
        got = count_lines(images_py, registry)
        if got != want:
            print(
                f'{images_py}: {registry} count is {got}, expected {want}',
                file=sys.stderr,
            )
            failed = True
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
