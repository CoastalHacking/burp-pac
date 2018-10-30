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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.github.markusbernhardt.proxy.selector.pac.PacScriptMethods;
import com.google.common.base.Strings;
import com.google.inject.Injector;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import us.coastalhacking.burp.pac.config.Server;

public class ProxyUtilsTest {

  private static final String OVERRIDE_LOCAL_IP = "127.0.0.1";
  private static String priorOverride;
  private static final String HTTP_PROXY_HOST = "http.proxyHost";
  private static final String HTTPS_PROXY_HOST = "https.proxyHost";
  private static String priorHttpProxyHost;
  private static String priorHttpsProxyHost;

  /**
   * Static setup.
   */
  @BeforeClass
  public static void beforeClass() {
    // https://github.com/MarkusBernhardt/proxy-vole#testing-pac
    priorOverride = System.getProperty(PacScriptMethods.OVERRIDE_LOCAL_IP);
    priorHttpProxyHost = System.getProperty(HTTP_PROXY_HOST);
    priorHttpsProxyHost = System.getProperty(HTTPS_PROXY_HOST);
    System.setProperty(PacScriptMethods.OVERRIDE_LOCAL_IP, OVERRIDE_LOCAL_IP);

  }

  /**
   * Static tear-down.
   */
  @AfterClass
  public static void afterClass() {
    if (!Strings.isNullOrEmpty(priorOverride)) {
      System.setProperty(PacScriptMethods.OVERRIDE_LOCAL_IP, priorOverride);
    }

    if (!Strings.isNullOrEmpty(priorHttpProxyHost)) {
      System.setProperty(HTTP_PROXY_HOST, priorHttpProxyHost);
    }

    if (!Strings.isNullOrEmpty(priorHttpsProxyHost)) {
      System.setProperty(HTTPS_PROXY_HOST, priorHttpsProxyHost);
    }
  }

  /*
   * Clean up each time before running a test
   */
  @Before
  public void before() {
    System.clearProperty(HTTP_PROXY_HOST);
    System.clearProperty(HTTPS_PROXY_HOST);
  }

  private static Proxy mockProxy(Proxy.Type type, String hostString, int port) {
    Proxy mockProxy = mock(Proxy.class);
    when(mockProxy.type()).thenReturn(type);
    // https://github.com/mockito/mockito/wiki/What's-new-in-Mockito-2#mock-the-unmockable-opt-in-mocking-of-final-classesmethods
    // InetSocketAddress.getHostString and getPort are final methods
    InetSocketAddress mockAddress = mock(InetSocketAddress.class);
    when(mockAddress.getHostString()).thenReturn(hostString);
    when(mockAddress.getPort()).thenReturn(port);
    when(mockProxy.address()).thenReturn(mockAddress);
    return mockProxy;
  }

  @Test
  public void shouldGetExpectedHttpProxyHost() throws Exception {
    String expectedProxyHost = "joshua";
    System.setProperty(HTTP_PROXY_HOST, expectedProxyHost);

    Injector injector =
        TestUtils.createInjectorWithModuleOverride(new TestUtils.EmptyProxySearchModule());
    ProxyUtils proxyUtils = injector.getInstance(ProxyUtils.class);
    List<Proxy> proxies = proxyUtils.getProxies(new URI("http://203.0.113.1:80"));
    Proxy proxy = proxies.get(0);
    InetSocketAddress address = (InetSocketAddress) proxy.address();
    assertEquals(expectedProxyHost, address.getHostString());
  }

  @Test
  public void shouldGetExpectedHttpsProxyHost() throws Exception {
    String expectedProxyHost = "joshua";
    String unexpectedProxyHost = "wopr";
    System.setProperty(HTTP_PROXY_HOST, unexpectedProxyHost);
    System.setProperty(HTTPS_PROXY_HOST, expectedProxyHost);

    Injector injector =
        TestUtils.createInjectorWithModuleOverride(new TestUtils.EmptyProxySearchModule());
    ProxyUtils proxyUtils = injector.getInstance(ProxyUtils.class);
    List<Proxy> proxies = proxyUtils.getProxies(new URI("https://198.51.100.100:80"));
    Proxy proxy = proxies.get(0);
    InetSocketAddress address = (InetSocketAddress) proxy.address();
    assertEquals(expectedProxyHost, address.getHostString());
  }

  @Test
  public void shouldNotGetProxyHost() throws Exception {
    Injector injector =
        TestUtils.createInjectorWithModuleOverride(new TestUtils.EmptyProxySearchModule());

    ProxyUtils proxyUtils = injector.getInstance(ProxyUtils.class);
    List<Proxy> proxies = proxyUtils.getProxies(new URI("https://192.0.2.254"));
    Proxy proxy = proxies.get(0);
    assertEquals(proxy.type(), Proxy.Type.DIRECT);

  }

  @Test
  public void shouldPopulateHttpProxy() {
    Injector injector = TestUtils.createInjector();
    ProxyUtils proxyUtils = injector.getInstance(ProxyUtils.class);
    Server server = new Server();
    List<Proxy> proxies = new ArrayList<>();
    Proxy.Type expectedType = Proxy.Type.HTTP;
    String expectedHostString = "joshua";
    int expectedPort = 399;
    proxies.add(mockProxy(expectedType, expectedHostString, expectedPort));
    proxyUtils.populateProxyForServer(server, proxies);
    assertEquals(server.getProxyHost(), expectedHostString);
    assertEquals(server.getProxyPort(), expectedPort);

  }

  @Test
  public void shouldNotPopulateDirectProxy() {
    Injector injector = TestUtils.createInjector();
    ProxyUtils proxyUtils = injector.getInstance(ProxyUtils.class);
    Server server = new Server();
    List<Proxy> proxies = new ArrayList<>();
    Proxy.Type unexpectedType = Proxy.Type.DIRECT;
    String unexpectedHostString = "worp";
    int unexpectedPort = 2364;
    proxies.add(mockProxy(unexpectedType, unexpectedHostString, unexpectedPort));
    proxyUtils.populateProxyForServer(server, proxies);
    assertTrue(Strings.isNullOrEmpty(server.getProxyHost()));

  }

  @Test
  public void shouldNotPopulateSocksProxy() {
    Injector injector = TestUtils.createInjector();
    ProxyUtils proxyUtils = injector.getInstance(ProxyUtils.class);
    Server server = new Server();
    List<Proxy> proxies = new ArrayList<>();
    Proxy.Type unexpectedType = Proxy.Type.SOCKS;
    String unexpectedHostString = "worp";
    int unexpectedPort = 2364;
    proxies.add(mockProxy(unexpectedType, unexpectedHostString, unexpectedPort));
    proxyUtils.populateProxyForServer(server, proxies);
    assertTrue(Strings.isNullOrEmpty(server.getProxyHost()));
  }

  @Test
  public void shouldPreferHttpProxyOverDirectProxy() {
    Injector injector = TestUtils.createInjector();
    ProxyUtils proxyUtils = injector.getInstance(ProxyUtils.class);
    Server server = new Server();
    List<Proxy> proxies = new ArrayList<>();
    Proxy.Type expectedType = Proxy.Type.HTTP;
    String expectedHostString = "joshua";
    int expectedPort = 399;
    Proxy.Type unexpectedType = Proxy.Type.DIRECT;
    String unexpectedHostString = "wopr";
    int unexpectedPort = 2364;
    // add the direct first to the list
    proxies.add(mockProxy(unexpectedType, unexpectedHostString, unexpectedPort));
    proxies.add(mockProxy(expectedType, expectedHostString, expectedPort));

    proxyUtils.populateProxyForServer(server, proxies);
    assertEquals(server.getProxyHost(), expectedHostString);
    assertEquals(server.getProxyPort(), expectedPort);

  }

}
