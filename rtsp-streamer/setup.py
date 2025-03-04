#!/usr/bin/env python3
"""
Setup script for YoLink Dashboard RTSP Server.
"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="yolink-dashboard",
    version="1.0.0",
    author="YoLink",
    author_email="info@example.com",
    description="RTSP server for YoLink sensor dashboard visualization",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/yolink-dashboard",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
    install_requires=[
        "Flask>=2.2.5",
        "Pillow>=10.3.0",
        "websocket-client==1.5.1",
        "Werkzeug>=3.0.6",
    ],
    entry_points={
        "console_scripts": [
            "yolink-dashboard=app.main:main",
        ],
    },
)