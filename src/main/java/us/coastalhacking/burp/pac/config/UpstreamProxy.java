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

import java.util.List;

public class UpstreamProxy {

  // default to false to honor project-specific options
  private boolean useUserOptions = false;
  private List<Server> servers;

  public boolean isUseUserOptions() {
    return useUserOptions;
  }

  public void setUseUserOptions(boolean useUserOptions) {
    this.useUserOptions = useUserOptions;
  }

  public List<Server> getServers() {
    return servers;
  }

  public void setServers(List<Server> servers) {
    this.servers = servers;
  }
}
