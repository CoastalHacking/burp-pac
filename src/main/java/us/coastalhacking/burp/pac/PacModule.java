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

package us.coastalhacking.burp.pac;

import burp.IBurpExtenderCallbacks;
import com.github.markusbernhardt.proxy.ProxySearch;
import com.google.inject.AbstractModule;
import java.net.ProxySelector;
import us.coastalhacking.burp.pac.config.ConfigUtils;

/**
 * The Guice module for this extension.
 */
public class PacModule extends AbstractModule {

  protected IBurpExtenderCallbacks callbacks;

  public PacModule(IBurpExtenderCallbacks callbacks) {
    super();
    this.callbacks = callbacks;
  }

  /*
   * (non-Javadoc)
   * 
   * @see com.google.inject.AbstractModule#configure()
   */
  @Override
  protected void configure() {

    bind(IBurpExtenderCallbacks.class).toInstance(this.callbacks);

    bind(ProxySearch.class).toProvider(DefaultProxySearchProvider.class);

    bind(ProxySelector.class).toProvider(DefaultProxySelectorProvider.class);

    bind(ConfigUtils.class);

    bind(ProxyUtils.class);

  }

}
