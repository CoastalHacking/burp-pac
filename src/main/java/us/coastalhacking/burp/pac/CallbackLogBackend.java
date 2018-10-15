package us.coastalhacking.burp.pac;

import burp.IBurpExtenderCallbacks;
import com.github.markusbernhardt.proxy.util.Logger.LogBackEnd;
import com.github.markusbernhardt.proxy.util.Logger.LogLevel;
import com.google.inject.Inject;

import java.text.MessageFormat;

public class CallbackLogBackend implements LogBackEnd {

  @Inject
  IBurpExtenderCallbacks callbacks;

  @Override
  public void log(Class<?> clazz, LogLevel loglevel, String msg, Object... params) {

    switch (loglevel) {
      case TRACE:
      case DEBUG:
      case INFO:
        callbacks.printOutput(MessageFormat.format(msg, params));
        break;
      case WARNING:
      case ERROR:
        callbacks.printError(MessageFormat.format(msg, params));
        break;
      // Unreachable
      default:
        callbacks.printError(String.format("Invalid level: %s", loglevel));
    }
  }
  
}
