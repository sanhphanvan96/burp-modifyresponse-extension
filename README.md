# Modify Response Burp Suite Extension

This Burp Suite extension allows you to modify HTTP responses based on specific criteria. It can replace parts of the response body or the entire body while keeping the headers intact.

## Features

- Modify HTTP responses for a specific host.
- Replace specific strings in the response body.
- Replace the entire response body if no specific string is provided.
- Preserve the original response headers.

## Installation

1. **Download and Install Jython**:
   - Download the Jython standalone JAR file from the [Jython website](https://www.jython.org/download.html).
   - In Burp Suite, go to the "Extender" tab, then the "Options" sub-tab.
   - Under "Python Environment", set the location of the Jython standalone JAR file.

2. **Load the Extension**:
   - Save the `ModifyResponse.py` script to your local machine.
   - In Burp Suite, go to the "Extender" tab, then the "Extensions" sub-tab.
   - Click on "Add".
   - Select "Python" as the extension type.
   - Load the `ModifyResponse.py` script file.

## Usage

1. **Configure the Extension**:
   - Open the `ModifyResponse.py` script.
   - Set the `TARGET_HOST`, `STRING_TO_REPLACE`, and `REPLACEMENT_STRING` constants as needed.

2. **Run Burp Suite**:
   - The extension will automatically modify responses for the specified host based on the configuration.

## Example Configuration

```python
# Configuration constants
 TARGET_HOST = "example.com"
 STRING_TO_REPLACE = None
 REPLACEMENT_STRING = "<head>The content has been modified!</head>"
```

```python
# Configuration constants
TARGET_HOST = "example.com"
STRING_TO_REPLACE = "<head>"
REPLACEMENT_STRING = "<head><script>alert(1)</script>"
```
