import os
import yaml
import asyncio

try:
    import aiofiles
except ImportError:
    aiofiles = None


def load_yaml(file_path: str) -> dict:
    """
    Synchronously load a YAML file.

    Args:
        file_path (str): Path to the YAML file.

    Returns:
        dict: Parsed YAML content or an empty dict if the file doesn't exist.
    """
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            return yaml.safe_load(file) or {}
    return {}


def save_to_yaml(file_path: str, data: dict) -> None:
    """
    Synchronously save data to a YAML file.

    Args:
        file_path (str): Path to the YAML file.
        data (dict): Data to be saved.
    """
    with open(file_path, 'w') as file:
        yaml.dump(data, file)


async def load_yaml_async(file_path: str) -> dict:
    """
    Asynchronously load a YAML file.

    If aiofiles is available, uses it for non-blocking I/O; otherwise wraps
    the synchronous load_yaml() function in the default executor.

    Args:
        file_path (str): Path to the YAML file.

    Returns:
        dict: Parsed YAML content or an empty dict if the file doesn't exist.
    """
    if aiofiles:
        if os.path.exists(file_path):
            async with aiofiles.open(file_path, 'r') as file:
                content = await file.read()
                return yaml.safe_load(content) or {}
        return {}
    else:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, load_yaml, file_path)


async def save_to_yaml_async(file_path: str, data: dict) -> None:
    """
    Asynchronously save data to a YAML file.

    If aiofiles is available, uses it for non-blocking I/O; otherwise wraps
    the synchronous save_to_yaml() function in the default executor.

    Args:
        file_path (str): Path to the YAML file.
        data (dict): Data to be saved.
    """
    if aiofiles:
        async with aiofiles.open(file_path, 'w') as file:
            content = yaml.dump(data)
            await file.write(content)
    else:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, save_to_yaml, file_path, data)
