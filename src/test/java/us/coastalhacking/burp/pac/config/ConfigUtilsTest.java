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

package us.coastalhacking.burp.pac.config;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import burp.IBurpExtenderCallbacks;
import com.google.inject.Injector;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;
import us.coastalhacking.burp.pac.Constants;
import us.coastalhacking.burp.pac.TestUtils;

public class ConfigUtilsTest {

  @Test
  public void shouldMatchServers() {
    Server a = new Server();
    Server b = new Server();
    String destinationHost = "a.b.c";
    a.setDestinationHost(destinationHost);
    b.setDestinationHost(destinationHost);
    assertEquals(a, b);
  }

  @Test
  public void shouldNotMatchServers() {
    Server a = new Server();
    Server b = new Server();
    a.setDestinationHost("a.b.c");
    b.setDestinationHost("a.b.b");
    assertNotEquals(a, b);
  }
  
  @Test
  public void shouldNotMatchServersNullOther() {
    Server a = new Server();
    Server b = null;
    assertNotEquals(a, b);
  }

  @Test
  public void shouldNotMatchServersNullThisHost() {
    Server a = new Server();
    Server b = new Server();
    b.setDestinationHost("a.b.b");
    assertNotEquals(a, b);
  }

  @Test
  public void shouldNotMatchServersDifferentObject() {
    Server a = new Server();
    Object b = new Object();
    assertNotEquals(a, b);
  }

  @Test
  public void shouldNotMatchServersNullHost() {
    Server a = new Server();
    Server b = new Server();
    a.setDestinationHost("a.b.c");
    assertNotEquals(a, b);
  }

  
  @Test
  public void shouldNotMatchServerProxyHost() {
    Server a = new Server();
    Server b = new Server();
    a.setProxyHost("1.2.3.4");
    assertNotEquals(a, b);     
  }
  
  @Test
  public void shouldMatchServerProxyHost() {
    Server a = new Server();
    Server b = new Server();
    String proxyHost = "a.b.c";
    a.setProxyHost(proxyHost);
    b.setProxyHost(proxyHost);
    assertEquals(a, b);
  }

  @Test
  public void shouldNotMatchServerProxyPort() {
    Server a = new Server();
    Server b = new Server();
    a.setProxyPort(8080);
    assertNotEquals(a, b);     
  }
  
  @Test
  public void shouldMatchServerProxyPort() {
    Server a = new Server();
    Server b = new Server();
    int proxyPort = 8080;
    a.setProxyPort(proxyPort);
    b.setProxyPort(proxyPort);
    assertEquals(a, b);
  }

  @Test
  public void shouldNotMatchServerEnabled() {
    Server a = new Server();
    Server b = new Server();
    a.setEnabled(true);
    assertNotEquals(a, b);     
  }
  
  @Test
  public void shouldMatchServerEnabled() {
    Server a = new Server();
    Server b = new Server();
    a.setEnabled(true);
    b.setEnabled(true);
    assertEquals(a, b);
  }
  
  @Test
  public void shouldDeserializeConfigWithServer() {

    String json = "{\n" + "    \"project_options\":{\n" + "        \"connections\":{\n"
        + "            \"upstream_proxy\":{\n" + "                \"servers\":[\n"
        + "                    {\n" + "                        \"auth_type\":\"NTLM_V2\",\n"
        + "                        \"destination_host\":\"123.123.123.123\",\n"
        + "                        \"domain\":\"domain\",\n"
        + "                        \"domain_hostname\":\"domain_hostname\",\n"
        + "                        \"enabled\":false,\n"
        + "                        \"password\":\"password\",\n"
        + "                        \"proxy_host\":\"localhost\",\n"
        + "                        \"proxy_port\":1080,\n"
        + "                        \"username\":\"hunter\"\n" + "                    }\n"
        + "                ],\n" + "                \"use_user_options\":false\n"
        + "            }\n" + "        }\n" + "    }\n" + "}";

    Server expected = TestUtils.getDisabledAuthServer();
    Injector injector = TestUtils.createInjector();
    IBurpExtenderCallbacks callbacks = injector.getInstance(IBurpExtenderCallbacks.class);
    when(callbacks.saveConfigAsJson(Constants.UPSTREAM_CONFIG_PATH)).thenReturn(json);
    ConfigUtils configUtils = injector.getInstance(ConfigUtils.class);

    Config config = configUtils.getConfig(Constants.UPSTREAM_CONFIG_PATH);
    Server actual =
        config.getProjectOptions().getConnections().getUpstreamProxy().getServers().get(0);

    assertEquals(expected.getDestinationHost(), actual.getDestinationHost());
    assertEquals(expected.isEnabled(), actual.isEnabled());
    assertEquals(expected.getProxyHost(), actual.getProxyHost());
    assertEquals(expected.getProxyPort(), actual.getProxyPort());
    assertEquals(expected.getAuthType(), actual.getAuthType());
    assertEquals(expected.getPassword(), actual.getPassword());
    assertEquals(expected.getUsername(), actual.getUsername());
    assertEquals(expected.getDomain(), actual.getDomain());
    assertEquals(expected.getDomainHostname(), actual.getDomainHostname());
  }

  @Test
  public void shouldLoadConfigViaCallback() {

    // mock
    Injector injector = TestUtils.createInjector();
    IBurpExtenderCallbacks callbacks = injector.getInstance(IBurpExtenderCallbacks.class);
    ConfigUtils configUtils = injector.getInstance(ConfigUtils.class);

    Config config = new Config();
    configUtils.saveConfig(config);
    verify(callbacks).loadConfigFromJson(any());
  }

  private Config buildConfigWithServer(Server server) {
    List<Server> servers = new ArrayList<>();
    servers.add(server);
    return buildConfigWithServers(servers);
  }

  private Config buildConfigWithServers(List<Server> servers) {
    Config config = new Config();
    config.setProjectOptions(new ProjectOptions());
    config.getProjectOptions().setConnections(new Connections());
    config.getProjectOptions().getConnections().setUpstreamProxy(new UpstreamProxy());
    config.getProjectOptions().getConnections().getUpstreamProxy().setServers(servers);
    return config;
  }

  @Test
  public void shouldHaveServerInConfig() {
    ConfigUtils configUtils = new ConfigUtils();
    Server expected = TestUtils.getGeneralServer();
    Config config = buildConfigWithServer(expected);
    assertTrue(configUtils.isServerInConfig(expected, config));
  }

  @Test
  public void shouldNotHaveServerInConfig() {
    ConfigUtils configUtils = new ConfigUtils();
    Config config = buildConfigWithServer(TestUtils.getGeneralServer());
    Server unexpected = new Server();
    unexpected.setDestinationHost("666.666.666.666");
    assertFalse(configUtils.isServerInConfig(unexpected, config));
  }

  @Test
  public void shouldAddServerToNewConfig() {
    ConfigUtils configUtils = new ConfigUtils();
    Server server = TestUtils.getGeneralServer();
    Config config = new Config();
    configUtils.addServerToConfig(server, config);
    assertEquals(server,
        config.getProjectOptions().getConnections().getUpstreamProxy().getServers().get(0));
  }

  @Test
  public void shouldSwitchUserOptionWhenServerAddedToExistingConfig() {
    Injector injector = TestUtils.createInjector();
    ConfigUtils configUtils = injector.getInstance(ConfigUtils.class);
    Server server = TestUtils.getGeneralServer();
    Config config = buildConfigWithServer(server);
    config.getProjectOptions().getConnections().getUpstreamProxy().setUseUserOptions(true);
    configUtils.addServerToConfig(server, config);
    assertFalse(config.getProjectOptions().getConnections().getUpstreamProxy().isUseUserOptions());
  }


  @Test
  public void shouldRemoveServersFromConfig() {
    Server serverA = new Server();
    serverA.setDestinationHost("123.123.123.123");
    serverA.setProxyHost("localhost");
    serverA.setProxyPort(1080);
    serverA.setEnabled(true);

    Server serverB = new Server();
    serverB.setDestinationHost("its.easy.as.abc");
    serverB.setProxyHost("localhost");
    serverB.setProxyPort(1080);
    serverB.setEnabled(true);

    List<Server> servers = new ArrayList<>();
    servers.add(serverA);
    servers.add(serverB);

    Config config = buildConfigWithServers(servers);
    ConfigUtils configUtils = new ConfigUtils();
    configUtils.removeServersFromConfig(servers, config);
    assertTrue(
        config.getProjectOptions().getConnections().getUpstreamProxy().getServers().isEmpty());
  }
}
