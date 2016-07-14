package burp;

import java.awt.Component;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;
import java.util.zip.GZIPInputStream;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;

import com.sun.xml.internal.org.jvnet.fastinfoset.FastInfosetSource;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory {

	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		helpers = callbacks.getHelpers();
		callbacks.setExtensionName("XML Fast Infoset Decoder");
		callbacks.registerMessageEditorTabFactory(this);
	}

	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		return new FastInfoSetDecoderTab(controller);
	}

	class FastInfoSetDecodeException extends RuntimeException {

		private static final long serialVersionUID = -701356174592436906L;

		public FastInfoSetDecodeException(Throwable e) {
			super(e);
		}
	}

	class FastInfoSetDecoderTab implements IMessageEditorTab {
		private ITextEditor txtInput;
		private byte[] currentMessage;
		private Transformer tx;

		public FastInfoSetDecoderTab(IMessageEditorController controller) {
			try {
				tx = TransformerFactory.newInstance().newTransformer();
				tx.setOutputProperty(OutputKeys.INDENT, "yes");
				tx.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
				tx.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
			} catch (Exception e) {
				throw new FastInfoSetDecodeException(e);
			}

			txtInput = callbacks.createTextEditor();
			txtInput.setEditable(false);
		}

		@Override
		public String getTabCaption() {
			return "FastInfoSet XML";
		}

		@Override
		public Component getUiComponent() {
			return txtInput.getComponent();
		}

		private boolean isMatch(List<String> headers, String name, String value) {
			for (String header : headers) {
				if (header.startsWith(name)) {
					return header.contains(value);
				}
			}
			return false;
		}

		@Override
		public boolean isEnabled(byte[] content, boolean isRequest) {
			List<String> headers = null;
			if (isRequest) {
				IRequestInfo request = helpers.analyzeRequest(content);
				headers = request.getHeaders();
			} else {
				IResponseInfo response = helpers.analyzeResponse(content);
				headers = response.getHeaders();
			}
			return isMatch(headers, "Content-Type", "application/fastinfoset");
		}

		private byte[] decodeFastInfoSetStream(byte[] content) {
			try (InputStream input = new ByteArrayInputStream(content);
					ByteArrayOutputStream output = new ByteArrayOutputStream()) {
				// Transform to convert the FI document to an XML document
				tx.transform(new FastInfosetSource(input), new StreamResult(output));
				return output.toByteArray();
			} catch (Exception e) {
				throw new FastInfoSetDecodeException(e);
			}
		}

		private byte[] unzip(byte[] content) {
			try (ByteArrayOutputStream out = new ByteArrayOutputStream();
					GZIPInputStream zipStream = new GZIPInputStream(new ByteArrayInputStream(content))) {
				byte[] buffer = new byte[1024];
				int length;
				while ((length = zipStream.read(buffer)) > 0) {
					out.write(buffer, 0, length);
				}
				return out.toByteArray();
			} catch (IOException e) {
				throw new FastInfoSetDecodeException(e);
			}
		}

		private byte[] decodeMessage(byte[] content, boolean isRequest) {
			int offset = -1;
			List<String> headers = null;
			if (isRequest) {
				IRequestInfo request = helpers.analyzeRequest(content);
				offset = request.getBodyOffset();
				headers = request.getHeaders();
			} else {
				IResponseInfo response = helpers.analyzeResponse(content);
				offset = response.getBodyOffset();
				headers = response.getHeaders();
			}

			byte[] body = Arrays.copyOfRange(content, offset, content.length);

			if (isMatch(headers, "Content-Encoding", "gzip")) {
				body = unzip(body);
			}

			return decodeFastInfoSetStream(body);
		}

		@Override
		public void setMessage(byte[] content, boolean isRequest) {
			if (content == null) {
				txtInput.setText(null);
			} else {
				byte[] message = decodeMessage(content, isRequest);
				txtInput.setText(message);
			}
			currentMessage = content;
		}

		@Override
		public byte[] getMessage() {
			return currentMessage;
		}

		@Override
		public boolean isModified() {
			return false;
		}

		@Override
		public byte[] getSelectedData() {
			return txtInput.getSelectedText();
		}
	}
}
