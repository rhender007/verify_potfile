from setuptools import setup, find_packages

setup(
    name="verify_potfile",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        'passlib>=1.7.4',
        'setuptools>=61.0'
    ],
    author="YourName",
    description="A tool to verify various hash formats from hashcat potfiles",
    python_requires='>=3.6',
    entry_points={
        'console_scripts': [
            'verify_potfile=verify_potfile.potfile:main',
        ],
    },
)
