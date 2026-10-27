
import subprocess
import re


def detect_php_version():
    """Detect the locally installed PHP CLI version."""

    try:
        result = subprocess.run(
            ["php", "-v"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False
        )

        if result.returncode != 0:
            return {
                "installed": False,
                "version": None,
                "message": "PHP is installed or configured incorrectly."
            }

        match = re.search(
            r"PHP\s+(\d+\.\d+\.\d+)",
            result.stdout
        )

        if not match:
            return {
                "installed": True,
                "version": None,
                "message": "PHP was found, but its version could not be parsed."
            }

        return {
            "installed": True,
            "version": match.group(1),
            "message": "PHP version detected successfully."
        }

    except FileNotFoundError:
        return {
            "installed": False,
            "version": None,
            "message": "PHP was not found in PATH."
        }

    except subprocess.TimeoutExpired:
        return {
            "installed": False,
            "version": None,
            "message": "PHP version detection timed out."
        }


if __name__ == "__main__":
    print(detect_php_version())
