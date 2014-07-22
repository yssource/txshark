from setuptools import setup, find_packages


setup(
    name="txshark",
    version="0.1.0",
    description="Python/Twisted wrapper for tshark",
    long_description=open('README.rst').read(),
    keywords="wireshark packet parsing twisted",
    author="Benjamin Bertrand",
    author_email="beenje@gmail.com",
    license="MIT",
    url="https://github.com/beenje/txshark",
    packages=find_packages(),
    install_requires=[
        "Twisted",
        "lxml",
    ],
    classifiers=['Development Status :: 4 - Beta',
                 'Topic :: Software Development',
                 'License :: OSI Approved :: MIT License',
                 'Intended Audience :: Developers',
                 'Programming Language :: Python'],
)
