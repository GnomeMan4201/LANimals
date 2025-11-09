from setuptools import find_packages, setup

# Read version from VERSION file
with open("VERSION", "r") as f:
    version = f.read().strip()

# Read requirements from requirements.txt
with open("requirements.txt", "r") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

# Read long description from README
with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="lanimals",
    version=version,
    description="Real-time Network Intelligence Suite for authorized security testing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="GnomeMan4201",
    url="https://github.com/GnomeMan4201/LANimals",
    license="GPL-3.0",
    packages=find_packages(exclude=["tests*", "docs*", "build*", "backup*"]),
    include_package_data=True,
    install_requires=requirements,
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "lanimals=LANimals:main",
            "LANimals=LANimals:main",
            "LANIMALS=LANimals:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
    keywords="network security reconnaissance penetration-testing recon scanning",
)
