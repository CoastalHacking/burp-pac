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
import com.google.common.base.Strings;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import java.net.Proxy;
import java.net.URI;
import java.util.Arrays;
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
  Map<Server, Server> cache;

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
    // Do not populate the key w/ the proxies
    final Server key = adapter.toServer(httpService);
    final Server realServer = adapter.toServer(httpService);
    
    // FIXME: Why are we synchronizing instead of using a concurrent hash map?
    synchronized (lock) {
      // always lookup proxy for server 
      // https://github.com/CoastalHacking/burp-pac/issues/43
      final URI uri = adapter.toUri(httpService);
      final List<Proxy> proxies = proxyUtils.getProxies(uri);
      proxyUtils.populateProxyForServer(realServer, proxies);    
      process(key, realServer, cache, configUtils, callbacks);
    }
  }

  /*
   * Returns dirty state for testing
   */
  boolean process(Server key, Server realServer, Map<Server, Server> cache,
      ConfigUtils configUtils, IBurpExtenderCallbacks callbacks) {

    // exit if in cache and equal
    Server oldValue = null;
    if (cache.containsKey(key)) {
      oldValue = cache.get(key);
      if (realServer.equals(oldValue)) {
        return false;
      }
    }

    // otherwise add / update
    cache.put(key, realServer);

    final Config config = configUtils.getConfig(Constants.UPSTREAM_CONFIG_PATH);
    boolean isDirty = removeStaleEntry(oldValue, config, configUtils);
    isDirty |= addProxyEntry(realServer, config, configUtils, callbacks);

    if (isDirty) {
      configUtils.saveConfig(config);
    }
    return isDirty;
  }

  boolean removeStaleEntry(Server oldValue, Config config, ConfigUtils configUtils) {
    boolean dirty = false;
    if (configUtils.isServerInConfig(oldValue, config)) {
      dirty = true;
      configUtils.removeServersFromConfig(Arrays.asList(oldValue), config);
    }
    return dirty;
  }

  boolean addProxyEntry(Server realServer, Config config, ConfigUtils configUtils,
      IBurpExtenderCallbacks callbacks) {
    boolean dirty = false;
    // only update config when a proxy server is added or if updating
    // due to different proxy server 
    if (!Strings.isNullOrEmpty(realServer.getProxyHost())) {

      if (configUtils.isServerInConfig(realServer, config)) {
        callbacks.printOutput(String.format(
            "Server already in project-level configuration (maybe added manually?), ignoring: %s",
            realServer));
      } else {
        callbacks.printOutput(
            String.format("Adding server to project-level configuration: %s", realServer));
        configUtils.addServerToConfig(realServer, config);
        dirty = true;
      }
    }
    return dirty;
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
          cache.keySet().stream().filter(s ->
              !Strings.isNullOrEmpty(s.getProxyHost())).collect(Collectors.toList());

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
