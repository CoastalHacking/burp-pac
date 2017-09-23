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

import burp.IBurpExtenderCallbacks;
import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.inject.Inject;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class ConfigUtils {

  @Inject
  private IBurpExtenderCallbacks callbacks;

  private Gson gson;

  /**
   * Utilities to add, modify, delete, and save Burp project-level configurations.
   */
  public ConfigUtils() {
    super();
    gson = new GsonBuilder().setPrettyPrinting()
        .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES).create();

  }

  public Config getConfig(String configPath) {
    String json = callbacks.saveConfigAsJson(configPath);
    return gson.fromJson(json, Config.class);
  }

  public void saveConfig(Config config) {
    String jsonConfig = gson.toJson(config);
    callbacks.loadConfigFromJson(jsonConfig);
  }

  /**
   * Tests to see if a server exists within a configuration.
   * 
   * @param server a server instance
   * @param config a configuration or null
   * @return true if a server is in a configuration, false otherwise
   */
  public boolean isServerInConfig(final Server server, final Config config) {
    return (config != null && config.getProjectOptions() != null
        && config.getProjectOptions().getConnections() != null
        && config.getProjectOptions().getConnections().getUpstreamProxy() != null
        && config.getProjectOptions().getConnections().getUpstreamProxy().getServers() != null
        && config.getProjectOptions().getConnections().getUpstreamProxy().getServers()
            .contains(server));
  }

  /**
   * Add a server to a configuration, populating the configuration if needed.
   * 
   * @param server a server instance
   * @param config a non-null configuration
   */
  public void addServerToConfig(final Server server, final Config config) {

    ProjectOptions projectOptions = config.getProjectOptions();
    if (projectOptions == null) {
      projectOptions = new ProjectOptions();
      config.setProjectOptions(projectOptions);
    }

    Connections connections = projectOptions.getConnections();
    if (connections == null) {
      connections = new Connections();
      projectOptions.setConnections(connections);
    }

    UpstreamProxy upstreamProxy = connections.getUpstreamProxy();
    if (upstreamProxy == null) {
      upstreamProxy = new UpstreamProxy();
      connections.setUpstreamProxy(upstreamProxy);
    }

    if (upstreamProxy.isUseUserOptions()) {
      // TODO consider adding UI option to toggle behavior here?
      // for now, override and log
      callbacks.printOutput("Overriding user options to enable project-level configuration!");

      // Required to honor project-specific options && Extender API does not support
      // user-options currently
      upstreamProxy.setUseUserOptions(false);
    }

    List<Server> servers = upstreamProxy.getServers();
    if (servers == null) {
      servers = new ArrayList<Server>();
      upstreamProxy.setServers(servers);
      // could opportunistically add server here but makes code a bit harder to read
    }

    if (servers.indexOf(server) != -1) {
      int index = servers.indexOf(server);
      servers.set(index, server);
    } else {
      servers.add(server);
    }
  }

  /**
   * Remove all servers from the existing project-level config and persist config.
   * 
   * @param servers a non-null collection of servers
   * @param config a configuration or null
   */
  public void removeServersFromConfig(final Collection<Server> servers, Config config) {

    // A user could have removed all of the upstream servers so double-check
    if (config != null && config.getProjectOptions() != null
        && config.getProjectOptions().getConnections() != null
        && config.getProjectOptions().getConnections().getUpstreamProxy() != null
        && config.getProjectOptions().getConnections().getUpstreamProxy().getServers() != null) {
      config.getProjectOptions().getConnections().getUpstreamProxy().getServers()
          .removeAll(servers);
    }
  }

}
