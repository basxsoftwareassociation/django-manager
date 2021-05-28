from setuptools import find_packages, setup


def readme():
    with open("README.rst") as f:
        return f.read()


setup(
    name="django-manager",
    version="0.1",
    description="basx management tool for django deployments",
    long_description=readme(),
    url="https://basx.dev",
    author="basx Software Development Co., Ltd.",
    author_email="info@basx.dev",
    license="Private",
    install_requires=["click", "python-nginx"],
    entry_points={"console_scripts": ["django-manager = django_manager.manager:cli"]},
    packages=find_packages(),
    setup_requires=["setuptools_scm"],
    use_scm_version=True,
    zip_safe=False,
    include_package_data=True,
)
