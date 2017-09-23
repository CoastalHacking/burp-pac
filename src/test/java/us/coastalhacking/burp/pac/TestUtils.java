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

import static org.mockito.Mockito.mock;

import burp.IBurpExtenderCallbacks;
import com.github.markusbernhardt.proxy.ProxySearch;
import com.github.markusbernhardt.proxy.ProxySearch.Strategy;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.Module;
import com.google.inject.Provider;
import com.google.inject.util.Modules;
import us.coastalhacking.burp.pac.config.ConfigUtils;
import us.coastalhacking.burp.pac.config.Server;

public class TestUtils {

  /**
   * Create a test injector with a default mock.
   * 
   * @return an injector
   */
  public static Injector createInjector() {
    IBurpExtenderCallbacks callbacks = mock(IBurpExtenderCallbacks.class);
    Injector injector = Guice.createInjector(new PacModule(callbacks));
    return injector;
  }

  /**
   * Create a test injector with a default mock and an overlay module.
   * 
   * @return an injector
   */
  public static Injector createInjectorWithModuleOverride(Module module) {
    IBurpExtenderCallbacks callbacks = mock(IBurpExtenderCallbacks.class);
    Injector injector =
        Guice.createInjector(Modules.override(new PacModule(callbacks)).with(module));
    return injector;
  }

  public static class EmptyProxySearchProvider implements Provider<ProxySearch> {

    @Override
    public ProxySearch get() {
      ProxySearch search = new ProxySearch();
      // Need at least one search strategy,
      // else the proxy selector returns null in the provider, which upsets Guice
      search.addStrategy(Strategy.JAVA);
      return search;
    }
  }

  public static class EmptyProxySearchModule extends AbstractModule {
    @Override
    protected void configure() {
      bind(ProxySearch.class).toProvider(EmptyProxySearchProvider.class);
    }
  }

  public static class MockPacModule extends AbstractModule {
    @Override
    protected void configure() {
      bind(Adapter.class).toInstance(mock(Adapter.class));
      bind(ProxyUtils.class).toInstance(mock(ProxyUtils.class));
      bind(ConfigUtils.class).toInstance(mock(ConfigUtils.class));
    }
  }

  /**
   * Return a basic server.
   * 
   * @return a basic server
   */
  public static Server getGeneralServer() {
    Server server = new Server();
    server.setDestinationHost("123.123.123.123");
    server.setProxyHost("localhost");
    server.setProxyPort(1080);
    server.setEnabled(true);
    return server;
  }

  /**
   * Return a server with authentication information.
   * 
   * @return a server with authentication information
   */
  public static Server getDisabledAuthServer() {
    Server server = new Server();
    server.setAuthType("NTLM_V2");
    server.setDomain("domain");
    server.setDomainHostname("domain_hostname");
    server.setPassword("password");
    server.setUsername("hunter");
    server.setDestinationHost("123.123.123.123");
    server.setProxyHost("localhost");
    server.setProxyPort(1080);
    server.setEnabled(false);
    return server;
  }
}
