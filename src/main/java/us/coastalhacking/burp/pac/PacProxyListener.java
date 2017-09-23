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
import burp.IExtensionStateListener;
import burp.IHttpService;
import burp.IInterceptedProxyMessage;
import burp.IProxyListener;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import java.net.Proxy;
import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import us.coastalhacking.burp.pac.config.Config;
import us.coastalhacking.burp.pac.config.ConfigUtils;
import us.coastalhacking.burp.pac.config.Server;

/**
 * Main entry point for this burp extension.
 */
@Singleton
public class PacProxyListener implements IProxyListener, IExtensionStateListener {

  // Make package public for testing
  Map<Server, Object> cache;

  @Inject
  private ConfigUtils configUtils;

  @Inject
  private ProxyUtils proxyUtils;

  @Inject
  private Adapter adapter;

  @Inject
  private IBurpExtenderCallbacks callbacks;

  private final Object lock = new Object();

  public PacProxyListener() {
    super();
    cache = new HashMap<>();
  }

  /*
   * (non-Javadoc)
   * 
   * @see burp.IProxyListener#processProxyMessage(boolean, burp.IInterceptedProxyMessage)
   */
  @Override
  public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {

    // exit fast
    if (!messageIsRequest) {
      return;
    }

    final IHttpService httpService = message.getMessageInfo().getHttpService();
    final Server server = adapter.toServer(httpService);
    synchronized (lock) {
      // exit fast
      if (cache.containsKey(server)) {
        return;
      }

      // cache server regardless of proxy lookup result
      cache.put(server, null);

      // lookup proxy for server
      final URI uri = adapter.toUri(httpService);
      final List<Proxy> proxies = proxyUtils.getProxies(uri);
      proxyUtils.populateProxyForServer(server, proxies);

      // only update config when a proxy server is added
      if (proxyUtils.hasProxy(server)) {
        final Config config = configUtils.getConfig(Constants.UPSTREAM_CONFIG_PATH);
        if (configUtils.isServerInConfig(server, config)) {
          callbacks.printOutput(String.format(
              "Server already in project-level configuration (maybe added manually?), ignoring: %s",
              server));
        } else {
          callbacks.printOutput(
              String.format("Adding server to project-level configuration: %s", server));
          configUtils.addServerToConfig(server, config);
          configUtils.saveConfig(config);
        }
      }

    }
  }

  /*
   * (non-Javadoc)
   * 
   * @see burp.IExtensionStateListener#extensionUnloaded()
   */
  @Override
  public void extensionUnloaded() {
    synchronized (lock) {
      // prune out servers that do not contain a proxy since they are cached regardless
      final List<Server> servers =
          cache.keySet().stream().filter(s -> proxyUtils.hasProxy(s)).collect(Collectors.toList());

      // only touch config if it contains a server this listener added
      final Config config = configUtils.getConfig(Constants.UPSTREAM_CONFIG_PATH);
      if (!servers.isEmpty()) {
        configUtils.removeServersFromConfig(servers, config);
        configUtils.saveConfig(config);
      }
      cache.clear();
    }
  }
}
