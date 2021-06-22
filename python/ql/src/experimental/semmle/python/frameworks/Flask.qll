/**
 * Provides classes modeling security-relevant aspects of the `flask` PyPI package.
 * See https://flask.palletsprojects.com/en/1.1.x/.
 */

private import python
private import semmle.python.dataflow.new.DataFlow
private import experimental.semmle.python.Concepts
private import semmle.python.ApiGraphs

private module Flask {
  private API::Node flaskMail() { result = API::moduleImport("flask_mail") }

  private API::Node flaskMailInstance() { result = flaskMail().getMember("Mail").getReturn() }

  private DataFlow::CallCfgNode flaskMessageCall() {
    result = flaskMail().getMember("Message").getACall()
  }

  private class FlaskMail extends DataFlow::CallCfgNode, EmailSender {
    /** A message variable to avoid multiple results in case consequential results are needed */
    DataFlow::CallCfgNode message;

    FlaskMail() {
      this =
        [flaskMailInstance(), flaskMailInstance().getMember("connect").getReturn()]
            .getMember("send")
            .getACall()
    }

    override DataFlow::Node getPlainTextBody() {
      result in [flaskMessageCall().getArg(2), flaskMessageCall().getArgByName("body")]
      or
      exists(DataFlow::AttrWrite bodyWrite |
        bodyWrite.getObject().getALocalSource() = flaskMessageCall() and
        bodyWrite.getAttributeName() = "body" and
        result = bodyWrite.getValue()
      )
    }

    override DataFlow::Node getHtmlBody() {
      result in [flaskMessageCall().getArg(3), flaskMessageCall().getArgByName("html")]
      or
      exists(DataFlow::AttrWrite bodyWrite |
        bodyWrite.getObject().getALocalSource() = flaskMessageCall() and
        bodyWrite.getAttributeName() = "html" and
        result = bodyWrite.getValue()
      )
    }

    override DataFlow::Node getTo() {
      result in [flaskMessageCall().getArg(1), flaskMessageCall().getArgByName("recipients")]
      or
      exists(DataFlow::AttrWrite bodyWrite |
        bodyWrite.getObject().getALocalSource() = flaskMessageCall() and
        bodyWrite.getAttributeName() = "recipients" and
        result = bodyWrite.getValue()
      )
    }

    override DataFlow::Node getFrom() {
      result in [flaskMessageCall().getArg(5), flaskMessageCall().getArgByName("sender")]
      or
      exists(DataFlow::AttrWrite bodyWrite |
        bodyWrite.getObject().getALocalSource() = flaskMessageCall() and
        bodyWrite.getAttributeName() = "sender" and
        result = bodyWrite.getValue()
      )
    }

    override DataFlow::Node getSubject() {
      result in [flaskMessageCall().getArg(0), flaskMessageCall().getArgByName("subject")]
      or
      exists(DataFlow::AttrWrite bodyWrite |
        bodyWrite.getObject().getALocalSource() = flaskMessageCall() and
        bodyWrite.getAttributeName() = "subject" and
        result = bodyWrite.getValue()
      )
    }
  }
}
