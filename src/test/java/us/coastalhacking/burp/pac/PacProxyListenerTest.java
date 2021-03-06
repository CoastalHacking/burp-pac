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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IInterceptedProxyMessage;
import com.google.inject.AbstractModule;
import com.google.inject.Injector;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Test;
import org.mockito.Mockito;
import us.coastalhacking.burp.pac.config.Config;
import us.coastalhacking.burp.pac.config.ConfigUtils;
import us.coastalhacking.burp.pac.config.Server;

public class PacProxyListenerTest {

  @Test
  public void shouldProcessProxyMessageNormalCase() {
    // Mock
    IInterceptedProxyMessage message = mock(IInterceptedProxyMessage.class);
    IHttpRequestResponse messageInfo = mock(IHttpRequestResponse.class);
    when(message.getMessageInfo()).thenReturn(messageInfo);
    Injector injector = TestUtils.createInjectorWithModuleOverride(new TestUtils.MockPacModule());
    Adapter mockAdapter = injector.getInstance(Adapter.class);
    Server server = TestUtils.getGeneralServer();
    URI mockUri = mock(URI.class);
    when(mockAdapter.toServer(any())).thenReturn(server);
    when(mockAdapter.toUri(any())).thenReturn(mockUri);
    ProxyUtils mockProxyUtils = injector.getInstance(ProxyUtils.class);
    List<Proxy> proxies = new ArrayList<>();
    when(mockProxyUtils.getProxies(any())).thenReturn(proxies);
    ConfigUtils mockConfigUtils = injector.getInstance(ConfigUtils.class);
    Config config = new Config();
    when(mockConfigUtils.getConfig(any())).thenReturn(config);
    when(mockConfigUtils.isServerInConfig(any(), any())).thenReturn(false);

    // Call
    PacProxyListener proxyListener = injector.getInstance(PacProxyListener.class);
    proxyListener.processProxyMessage(/* messageIsRequest */true, message);

    // Verify
    verify(mockConfigUtils, times(1)).addServerToConfig(server, config);
    verify(mockConfigUtils, times(1)).saveConfig(config);
    assertTrue(proxyListener.cache.containsKey(server));
  }

  @Test
  public void shouldNotProcessProxyMessageResponseMessage() {
    // Mock
    IInterceptedProxyMessage message = mock(IInterceptedProxyMessage.class);
    PacProxyListener proxyListener = new PacProxyListener();

    // Call
    proxyListener.processProxyMessage(/* messageIsRequest */false, message);

    // Verify
    verify(message, never()).getMessageInfo();
  }

  @Test
  public void shouldCacheServerNoProxiesAndReturnQuicklyOnSecondRun() {
    // Mock
    IInterceptedProxyMessage message = mock(IInterceptedProxyMessage.class);
    IHttpRequestResponse messageInfo = mock(IHttpRequestResponse.class);
    when(message.getMessageInfo()).thenReturn(messageInfo);
    Injector injector = TestUtils.createInjectorWithModuleOverride(new TestUtils.MockPacModule());
    Adapter mockAdapter = injector.getInstance(Adapter.class);
    Server server = TestUtils.getGeneralServer();
    URI mockUri = mock(URI.class);
    when(mockAdapter.toServer(any())).thenReturn(server);
    when(mockAdapter.toUri(any())).thenReturn(mockUri);
    ProxyUtils mockProxyUtils = injector.getInstance(ProxyUtils.class);
    List<Proxy> proxies = new ArrayList<>();
    when(mockProxyUtils.getProxies(any())).thenReturn(proxies);

    // First call
    PacProxyListener proxyListener = injector.getInstance(PacProxyListener.class);
    proxyListener.processProxyMessage(/* messageIsRequest */true, message);

    // Second call
    proxyListener.processProxyMessage(/* messageIsRequest */true, message);

    // Verify methods are called the correct number of times
    verify(mockAdapter, times(2)).toUri(any());
  }

  @Test
  public void shouldProcessNotAddToConfig() {
    // Mock
    Injector injector = TestUtils.createInjectorWithModuleOverride(new TestUtils.MockPacModule());
    Server realServer = TestUtils.getGeneralServer();
    Server key = new Server();
    key.setDestinationHost(realServer.getDestinationHost());
    ProxyUtils mockProxyUtils = injector.getInstance(ProxyUtils.class);
    List<Proxy> proxies = new ArrayList<>();
    when(mockProxyUtils.getProxies(any())).thenReturn(proxies);
    ConfigUtils mockConfigUtils = injector.getInstance(ConfigUtils.class);
    Config config = new Config();
    when(mockConfigUtils.getConfig(any())).thenReturn(config);
    when(mockConfigUtils.isServerInConfig(any(), any())).thenReturn(true);
    IBurpExtenderCallbacks callbacks = mock(IBurpExtenderCallbacks.class);
    Map<Server, Server> cache = new HashMap<>();
    cache.put(key, realServer);

    // Call
    PacProxyListener proxyListener = injector.getInstance(PacProxyListener.class);
    proxyListener.process(key, realServer, cache, mockConfigUtils, callbacks);

    // Verify methods not called
    verify(mockConfigUtils, never()).addServerToConfig(realServer, config);
    verify(mockConfigUtils, never()).saveConfig(config);
  }

  @Test
  public void shouldUnloadExtensionWithServers() {
    // Mock
    IInterceptedProxyMessage message = mock(IInterceptedProxyMessage.class);
    IHttpRequestResponse messageInfo = mock(IHttpRequestResponse.class);
    when(message.getMessageInfo()).thenReturn(messageInfo);
    Injector injector = TestUtils.createInjectorWithModuleOverride(new TestUtils.MockPacModule());

    ConfigUtils mockConfigUtils = injector.getInstance(ConfigUtils.class);
    Config config = new Config();
    when(mockConfigUtils.getConfig(any())).thenReturn(config);
    Server server = TestUtils.getGeneralServer();
    PacProxyListener proxyListener = injector.getInstance(PacProxyListener.class);
    // ignore locking
    proxyListener.cache.put(server, server);

    // Call
    proxyListener.extensionUnloaded();

    // Verify methods called
    verify(mockConfigUtils, times(1)).removeServersFromConfig(any(), any());
    verify(mockConfigUtils, times(1)).saveConfig(any());
    assertTrue(proxyListener.cache.isEmpty());
  }

  @Test
  public void shouldUnloadExtensionWithNoServers() {
    // Mock
    IInterceptedProxyMessage message = mock(IInterceptedProxyMessage.class);
    IHttpRequestResponse messageInfo = mock(IHttpRequestResponse.class);
    when(message.getMessageInfo()).thenReturn(messageInfo);
    Injector injector = TestUtils.createInjectorWithModuleOverride(new TestUtils.MockPacModule());

    ConfigUtils mockConfigUtils = injector.getInstance(ConfigUtils.class);
    Config config = new Config();
    when(mockConfigUtils.getConfig(any())).thenReturn(config);
    Server server = TestUtils.getGeneralServer();
    Server key = new Server();
    key.setDestinationHost(server.getDestinationHost());
    PacProxyListener proxyListener = injector.getInstance(PacProxyListener.class);
    // ignore locking
    proxyListener.cache.put(key, server);

    // Call
    proxyListener.extensionUnloaded();

    // Verify methods called
    verify(mockConfigUtils, never()).removeServersFromConfig(any(), any());
    verify(mockConfigUtils, never()).saveConfig(any());
    assertTrue(proxyListener.cache.isEmpty());
  }

  private static class SpyMockModule extends AbstractModule {
    @Override
    protected void configure() {
      bind(Adapter.class).toInstance(mock(Adapter.class));
      bind(ProxyUtils.class).toInstance(Mockito.spy(new ProxyUtils()));
      bind(ConfigUtils.class).toInstance(Mockito.spy(new ConfigUtils()));
    }
  }

  @Test
  public void shouldUnloadExtensionWithExistingServerIntact() {
    final String existingDestinationHost = "existing.example.com";
    final String existingProxyHost = "localhost";
    final int existingPort = 1100;

    // create a configuration with a server
    Server existingServer = new Server();
    existingServer.setProxyHost(existingProxyHost);
    existingServer.setProxyPort(existingPort);
    existingServer.setEnabled(true);
    existingServer.setDestinationHost(existingDestinationHost);

    // mock
    IInterceptedProxyMessage message = mock(IInterceptedProxyMessage.class);
    IHttpRequestResponse messageInfo = mock(IHttpRequestResponse.class);
    when(message.getMessageInfo()).thenReturn(messageInfo);
    Injector injector = TestUtils.createInjectorWithModuleOverride(new SpyMockModule());
    Adapter mockAdapter = injector.getInstance(Adapter.class);
    Server newServer = TestUtils.getGeneralServer();
    URI mockUri = mock(URI.class);
    when(mockAdapter.toServer(any())).thenReturn(newServer);
    when(mockAdapter.toUri(any())).thenReturn(mockUri);
    ProxyUtils spyProxyUtils = injector.getInstance(ProxyUtils.class);
    List<Proxy> proxies = new ArrayList<>();
    Mockito.doReturn(proxies).when(spyProxyUtils).getProxies(any());
    ConfigUtils spyConfigUtils = injector.getInstance(ConfigUtils.class);
    Config realConfig = new Config();
    spyConfigUtils.addServerToConfig(existingServer, realConfig);
    Mockito.doReturn(realConfig).when(spyConfigUtils).getConfig(any());

    // call processProxyMessage
    PacProxyListener proxyListener = injector.getInstance(PacProxyListener.class);
    proxyListener.processProxyMessage(/* messageIsRequest */true, message);

    // assert configuration
    assertTrue(spyConfigUtils.isServerInConfig(existingServer, realConfig));
    assertTrue(spyConfigUtils.isServerInConfig(newServer, realConfig));

    // call extensionUnloaded
    proxyListener.extensionUnloaded();

    // assert configuration
    assertTrue(spyConfigUtils.isServerInConfig(existingServer, realConfig));
    assertFalse(spyConfigUtils.isServerInConfig(newServer, realConfig));

  }

  @Test
  public void shouldRemoveServerWithProxyNoAdd() {
    // Mock
    Injector injector = TestUtils.createInjectorWithModuleOverride(new TestUtils.MockPacModule());
    Server oldValue = TestUtils.getGeneralServer();
    Map<Server, Server> cache = new HashMap<>();
    Server key = new Server();
    key.setDestinationHost(oldValue.getDestinationHost());
    cache.put(key, oldValue);
    ConfigUtils mockConfigUtils = injector.getInstance(ConfigUtils.class);
    Config config = new Config();
    when(mockConfigUtils.getConfig(any())).thenReturn(config);
    when(mockConfigUtils.isServerInConfig(eq(oldValue), eq(config))).thenReturn(true);
    Server newServer = new Server();
    newServer.setDestinationHost(key.getDestinationHost());
    when(mockConfigUtils.isServerInConfig(eq(newServer), eq(config))).thenReturn(false);
    IBurpExtenderCallbacks callbacks = mock(IBurpExtenderCallbacks.class);

    // Call
    assertTrue(cache.containsValue(oldValue));
    PacProxyListener proxyListener = injector.getInstance(PacProxyListener.class);
    proxyListener.process(key, newServer, cache, mockConfigUtils, callbacks);

    // Verify
    verify(mockConfigUtils, times(1)).removeServersFromConfig(any(), any());
    assertFalse(cache.containsValue(oldValue));
    verify(mockConfigUtils, times(1)).saveConfig(any());
    // Second time no proxy server
    verify(mockConfigUtils, times(0)).addServerToConfig(any(), any());

  }

  Proxy mockProxy(Proxy.Type type, String proxyHost, int proxyPort) {
    Proxy proxy = mock(Proxy.class);
    when(proxy.type()).thenReturn(type);

    if (type == Proxy.Type.HTTP) {
      InetSocketAddress mockAddress = mock(InetSocketAddress.class);
      when(mockAddress.getHostString()).thenReturn(proxyHost);
      when(mockAddress.getPort()).thenReturn(proxyPort);
      when(proxy.address()).thenReturn(mockAddress);
    }
    return proxy;
  }
}
