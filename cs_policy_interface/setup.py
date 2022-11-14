import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="cs_policy_interface",
    version="1.0",
    author="CoreStack",
    author_email="info@corestack.io",
    description="Client for CS Policy Interface",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://review.coestack.in/cs_policy_interface",
    packages=['cs_policy_interface', 'cs_policy_interface.rules'],
    package_data={'cs_policy_interface': ['data/*.json']},
    classifiers=[
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.9",
        "Operating System :: OS Independent",
    ]
)
