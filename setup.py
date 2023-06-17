from setuptools import setup, find_packages

setup(
    name='jhook',
    version='1.0',
    include_package_data=True,
    packages=find_packages(),
    install_requires=[
        'bcrypt',
        'Flask',
        'Flask-SQLAlchemy',
        'gevent',
        'pyTelegramBotAPI',
        'SQLAlchemy-serializer'
    ],
    entry_points={
        "console_scripts": [
            "jhook = jhook.app:main",
        ]
    }
)