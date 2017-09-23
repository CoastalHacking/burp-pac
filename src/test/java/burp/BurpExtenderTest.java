/*******************************************************************************
 * Copyright 2017 Coastal Hacking
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 ******************************************************************************/

package burp;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import org.junit.Test;
import us.coastalhacking.burp.pac.PacProxyListener;

public class BurpExtenderTest {

  @Test
  public void shouldRegisterExtenderCallbacks() {

    // Mock
    IBurpExtenderCallbacks callbacks = mock(IBurpExtenderCallbacks.class);
    BurpExtender extender = new BurpExtender();

    // Call
    extender.registerExtenderCallbacks(callbacks);

    // Verify
    PacProxyListener proxyListener = extender.injector.getInstance(PacProxyListener.class);
    verify(callbacks).registerProxyListener(proxyListener);
    verify(callbacks).registerExtensionStateListener(proxyListener);
    verify(callbacks).setExtensionName(eq(BurpExtender.EXTENSION_NAME));
  }

}
