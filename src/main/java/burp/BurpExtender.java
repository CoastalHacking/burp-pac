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

import com.google.inject.Guice;
import com.google.inject.Injector;
import us.coastalhacking.burp.pac.PacModule;
import us.coastalhacking.burp.pac.PacProxyListener;

public class BurpExtender implements IBurpExtender {

  // make package public for testing
  Injector injector;

  public static final String EXTENSION_NAME = "Proxy auto-config (PAC) support";

  /*
   * (non-Javadoc)
   * 
   * @see burp.IBurpExtender#registerExtenderCallbacks(burp.IBurpExtenderCallbacks)
   */
  @Override
  public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

    injector = Guice.createInjector(new PacModule(callbacks));
    PacProxyListener pacProxyListener = injector.getInstance(PacProxyListener.class);
    callbacks.registerProxyListener(pacProxyListener);
    callbacks.registerExtensionStateListener(pacProxyListener);
    callbacks.setExtensionName(EXTENSION_NAME);
  }
}
