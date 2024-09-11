from burp import IBurpExtender, IProxyListener
from java.io import PrintWriter

class BurpExtender(IBurpExtender, IProxyListener):
    # Configuration constants
    TARGET_HOST = "example.com"
    STRING_TO_REPLACE = None
    REPLACEMENT_STRING = "<head>The content has been modified!</head>"

    def registerExtenderCallbacks(self, callbacks):
        # Set extension name
        extName = "Modify Response"
        callbacks.setExtensionName(extName)

        # Keep a reference to our callbacks object and add helpers
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # Obtain our output streams
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        # Register ourselves as a Proxy listener
        callbacks.registerProxyListener(self)

        # Print extension name
        self._stdout.println("%s extension loaded" % extName)

    def processProxyMessage(self, messageIsRequest, message):
        try:
            # Check if it's a response
            if not messageIsRequest:
                # Retrieve IHttpRequestResponse object
                httpRequestResponse = message.getMessageInfo()
                # Determine the host
                host = httpRequestResponse.getHttpService().getHost()

                # Only replace on matching host
                if host == self.TARGET_HOST:
                    # Fetch response and analyze it
                    responseBytes = httpRequestResponse.getResponse()
                    responseInfo = self._helpers.analyzeResponse(responseBytes)

                    # Get headers and body
                    headers = responseInfo.getHeaders()
                    bodyOffset = responseInfo.getBodyOffset()
                    bodyBytes = responseBytes[bodyOffset:]
                    bodyString = self._helpers.bytesToString(bodyBytes)

                    # If STRING_TO_REPLACE is None, replace the entire body
                    if self.STRING_TO_REPLACE is None:
                        modifiedBodyString = self.REPLACEMENT_STRING
                    else:
                        # Match and replace in the body
                        if self.STRING_TO_REPLACE in bodyString:
                            modifiedBodyString = bodyString.replace(self.STRING_TO_REPLACE, self.REPLACEMENT_STRING, 1)
                        else:
                            modifiedBodyString = bodyString

                    # Convert modified body back to bytes
                    modifiedBodyBytes = self._helpers.stringToBytes(modifiedBodyString)

                    # Rebuild the response with the original headers and modified body
                    newResponseBytes = self._helpers.buildHttpMessage(headers, modifiedBodyBytes)
                    httpRequestResponse.setResponse(newResponseBytes)

                    # Log the modification
                    self._stdout.println("Modified response for host: %s" % host)

        except Exception as e:
            self._stderr.println("Error processing proxy message: %s" % str(e))
