# Publishing IED Inspector as a pip package

Install for users afterwards:

    pip install ied-inspector          # from PyPI or your private index
    ied-inspector                      # starts the tool and opens the browser

## 0. Decide where it goes

| Target | Who can install | Use when |
|---|---|---|
| **pypi.org** (public) | anyone in the world, source code readable | only with approval to release the tool publicly (open-source licence) |
| **Private index** (Azure Artifacts, GitLab/GitHub Packages, Nexus, Artifactory, devpi) | only people with access | internal company tool |
| **Wheel on a file share** | anyone who can read the share | quickest internal option, no server |

The project is released under the MIT licence (`LICENSE`, `license = "MIT"` in `pyproject.toml`).

Checklist before the first public upload:
- [ ] The name is free on pypi.org (step 2a.1).
- [ ] The repository exists (GitHub/GitLab) and `[project.urls]` in `pyproject.toml` is filled in.
- [ ] `__version__` in `ied_inspector/__init__.py` is the version you want to release.
- [ ] No private material is in the folder: customer SCD files, IP plans, pcaps from real sites. Only the fictional `demo_substation.scd` is included.

## 1. Build (same for every target)

Windows: double-click `build_package.bat`.  Any OS:

    python -m pip install --upgrade build twine
    python -m build
    python -m twine check dist/*

Result: `dist/ied_inspector-<version>-py3-none-any.whl` and `dist/ied_inspector-<version>.tar.gz`.
The version comes from `ied_inspector/__init__.py` (`__version__`). Raise it for every upload; an index never accepts the same version twice.

## 2a. Public PyPI

1. Check the name is free: https://pypi.org/project/ied-inspector/ should show "Not Found". If it is taken, change `name =` in `pyproject.toml` (for example `iec61850-ied-inspector`).
2. Create accounts on https://test.pypi.org and https://pypi.org (two separate accounts) and enable two-factor authentication (required).
3. Create an API token on each site: Account settings → API tokens → scope "Entire account" (the first upload creates the project; afterwards replace the token with one scoped to the project).
4. Test upload first:

        python -m twine upload --repository testpypi dist/*
        # user name: __token__   password: the pypi-... token from test.pypi.org
        pip install --index-url https://test.pypi.org/simple/ ied-inspector

5. Real upload:

        python -m twine upload dist/*

6. Optional: keep the token in `%USERPROFILE%\.pypirc` (Windows) / `~/.pypirc`:

        [pypi]
        username = __token__
        password = pypi-AgEI...

        [testpypi]
        username = __token__
        password = pypi-AgEN...

   Never commit this file or the token to git.

Better for later releases: "Trusted Publishing" with the included `.github/workflows/publish.yml`. Configure the publisher on pypi.org once (see the comment at the top of the file), then every `git tag v0.6.1 && git push --tags` builds, tests and uploads automatically, without any stored token.

## 2b. Private index (internal)

    python -m twine upload --repository-url <your-index-upload-url> dist/*
    pip install --index-url <your-index-simple-url> ied-inspector

- Azure Artifacts: create a feed, then "Connect to feed → twine" shows the exact URL and token setup.
- GitLab: `https://gitlab.example.com/api/v4/projects/<id>/packages/pypi` (upload) and `.../packages/pypi/simple` (install), with a deploy token.
- Nexus / Artifactory: create a "pypi (hosted)" repository; the UI shows both URLs.

## 2c. File share (no server)

Copy the `.whl` to a share, then:

    pip install \\server\share\ied_inspector-0.6.0-py3-none-any.whl
    # or a folder with several versions:
    pip install --no-index --find-links \\server\share\ied-inspector ied-inspector

## What the package contains

The `ied_inspector` package, the web interface (`ied_inspector/web/index.html`) and the demo SCD. There are no dependencies: standard library only.
Npcap (Windows) and libiec61850 are not included, because they are not pip packages. The README explains them.
For PCs without Python, the one-file exe (`build_windows_exe.bat`) is still the better choice.
