from setuptools import setup, find_packages

setup(
    name="lanimals",
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "psutil",
        "faker",
        "colorama",
        "requests",
        "rich",
        "flask",
        "scapy"
    ],
    entry_points={
        "console_scripts": [
            "lanimals_ui=lanimals_ui:main",
            "lanimals_recon=core.lanimals_recon:main",
            "lanimals_vulscan=modules.vulscan:main",
            "lanimals_tripwire=modules.tripwire_monitor:main",
            "lanimals_asciiroll=modules.asciiroll:main",
            "lanimals_fortress=modules.fortress:main",
            "lanimals_lootlog=modules.loot_logger:main",
            "lanimals_sysinfo=core.sysinfo:main",
        ],
    },
)
