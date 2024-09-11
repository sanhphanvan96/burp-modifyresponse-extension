from burp import IBurpExtender, IProxyListener, ITab
from java.io import PrintWriter
from javax.swing import JPanel, JLabel, JTextField, JButton, BoxLayout, JTextArea, JScrollPane, BorderFactory
from java.awt import Dimension, Color

class BurpExtender(IBurpExtender, IProxyListener, ITab):
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

        # Create and add the UI tab
        self._panel = JPanel()
        self._panel.setLayout(BoxLayout(self._panel, BoxLayout.Y_AXIS))

        self._panel.add(JLabel("Target Host:"))
        self._targetHostField = JTextField(20)
        self._targetHostField.setMaximumSize(Dimension(200, 30))
        self._targetHostField.setText("example.com")
        # self._targetHostField.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        self._targetHostField.setBorder(BorderFactory.createLineBorder(Color.BLACK))
        self._panel.add(self._targetHostField)

        self._panel.add(JLabel("String to Replace (or leave empty for entire body replacement):"))
        self._stringToReplaceArea = JTextArea(5, 20)
        self._stringToReplaceArea.setLineWrap(True)
        self._stringToReplaceArea.setWrapStyleWord(True)
        self._stringToReplaceArea.setText("<body>")
        self._panel.add(JScrollPane(self._stringToReplaceArea))

        self._panel.add(JLabel("Replacement String:"))
        self._replacementStringArea = JTextArea(5, 20)
        self._replacementStringArea.setLineWrap(True)
        self._replacementStringArea.setWrapStyleWord(True)
        self._replacementStringArea.setText("Enter replacement string here...")
        self._panel.add(JScrollPane(self._replacementStringArea))

        self._saveButton = JButton("Save", actionPerformed=self.saveConfig)
        self._panel.add(self._saveButton)

        callbacks.addSuiteTab(self)

        # Print extension name
        self._stdout.println("%s extension loaded" % extName)

        # Initialize configuration
        self.TARGET_HOST = "example.com"
        self.STRING_TO_REPLACE = None
        self.REPLACEMENT_STRING = "<head><script>alert(1)</script>"

    def getTabCaption(self):
        return "Modify Response"

    def getUiComponent(self):
        return self._panel

    def saveConfig(self, event):
        self.TARGET_HOST = self._targetHostField.getText()
        self.STRING_TO_REPLACE = self._stringToReplaceArea.getText()
        self.REPLACEMENT_STRING = self._replacementStringArea.getText()
        self._stdout.println("Configuration saved:")
        self._stdout.println("TARGET_HOST: %s" % self.TARGET_HOST)
        self._stdout.println("STRING_TO_REPLACE: %s" % self.STRING_TO_REPLACE)
        self._stdout.println("REPLACEMENT_STRING: %s" % self.REPLACEMENT_STRING)

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
                    if not self.STRING_TO_REPLACE:
                        modifiedBodyString = self.REPLACEMENT_STRING
                    else:
                        # Match and replace in the body
                        if self.STRING_TO_REPLACE in bodyString:
                            modifiedBodyString = bodyString.replace(self.STRING_TO_REPLACE, self.REPLACEMENT_STRING, 1)
                        else:
                            modifiedBodyString = bodyString

                    # Convert modified body back to bytes
                    modifiedBodyBytes = self._helpers.stringToBytes(modifiedBodyString)

                    # Rebuild the response with the original headers and modified bodyab
                    newResponseBytes = self._helpers.buildHttpMessage(headers, modifiedBodyBytes)
                    httpRequestResponse.setResponse(newResponseBytes)

                    # Log the modification
                    self._stdout.println("Modified response for host: %s" % host)

        except Exception as e:
            self._stderr.println("Error processing proxy message: %s" % str(e))
