package us.coastalhacking.burp.pac;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;

import burp.IBurpExtenderCallbacks;
import com.github.markusbernhardt.proxy.util.Logger;
import com.github.markusbernhardt.proxy.util.Logger.LogBackEnd;
import com.github.markusbernhardt.proxy.util.Logger.LogLevel;
import com.google.inject.Injector;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

public class CallbackLogBackendTest {

  @Test
  public void shouldLog() throws Exception {
    final Injector injector = TestUtils.createInjector();
    final ArgumentCaptor<String> print = ArgumentCaptor.forClass(String.class);
    final IBurpExtenderCallbacks callbacks = injector.getInstance(IBurpExtenderCallbacks.class);
    final LogBackEnd backend = injector.getInstance(LogBackEnd.class);
    Logger.setBackend(backend);
    final String expected = "test msg";
    final String message = "{0} {1}";
    final Object[] params = new Object[] {"test", "msg"};
    
    // Test printOutput log messages
    for (LogLevel level : new LogLevel[] {LogLevel.TRACE, LogLevel.DEBUG, LogLevel.INFO}) {
      // Execute
      Logger.log(CallbackLogBackendTest.class, level, message, params);
  
      // Verify
      verify(callbacks, atLeastOnce()).printOutput(print.capture());
      // getValue() obtains the last capture
      assertEquals(expected, print.getValue());
      
    }

    // Test printError messages
    for (LogLevel level : new LogLevel[] {LogLevel.WARNING, LogLevel.ERROR}) {
      // Execute
      Logger.log(CallbackLogBackendTest.class, level, message, params);
  
      // Verify
      verify(callbacks, atLeastOnce()).printError(print.capture());
      // getValue() obtains the last capture
      assertEquals(expected, print.getValue());
      
    }

  }

}
