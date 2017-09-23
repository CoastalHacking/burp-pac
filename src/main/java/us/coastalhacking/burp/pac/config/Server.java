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

public class Server {

  // General settings
  private int proxyPort;
  private String proxyHost;
  private boolean enabled;
  private String destinationHost;
  // Authentication-related
  private String authType;
  private String username;
  private String password;
  private String domain;
  private String domainHostname;

  public int getProxyPort() {
    return proxyPort;
  }

  public void setProxyPort(int proxyPort) {
    this.proxyPort = proxyPort;
  }

  public String getProxyHost() {
    return proxyHost;
  }

  public void setProxyHost(String proxyHost) {
    this.proxyHost = proxyHost;
  }

  public boolean isEnabled() {
    return enabled;
  }

  public void setEnabled(boolean enabled) {
    this.enabled = enabled;
  }

  public String getDestinationHost() {
    return destinationHost;
  }

  public void setDestinationHost(String destinationHost) {
    this.destinationHost = destinationHost;
  }

  public String getAuthType() {
    return authType;
  }

  public void setAuthType(String authType) {
    this.authType = authType;
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }

  public String getDomain() {
    return domain;
  }

  public void setDomain(String domain) {
    this.domain = domain;
  }

  public String getDomainHostname() {
    return domainHostname;
  }

  public void setDomainHostname(String domainHostname) {
    this.domainHostname = domainHostname;
  }

  /*
   * (non-Javadoc)
   * 
   * @see java.lang.Object#hashCode()
   */
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((destinationHost == null) ? 0 : destinationHost.hashCode());
    return result;
  }

  /*
   * (non-Javadoc)
   * 
   * @see java.lang.Object#equals(java.lang.Object)
   */
  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    Server other = (Server) obj;
    if (destinationHost == null) {
      if (other.destinationHost != null) {
        return false;
      }
    } else if (!destinationHost.equals(other.destinationHost)) {
      return false;
    }
    return true;
  }

  /*
   * (non-Javadoc)
   * 
   * @see java.lang.Object#toString()
   */
  @Override
  public String toString() {
    return "Server [proxyPort=" + proxyPort + ", proxyHost=" + proxyHost + ", enabled=" + enabled
        + ", destinationHost=" + destinationHost + "]";
  }

}
