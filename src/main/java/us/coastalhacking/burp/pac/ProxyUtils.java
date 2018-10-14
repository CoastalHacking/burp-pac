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
import com.google.common.base.Strings;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.URI;
import java.util.List;
import us.coastalhacking.burp.pac.config.Server;

@Singleton
public class ProxyUtils {

  @Inject
  private ProxySelector proxySelector;

  @Inject
  private IBurpExtenderCallbacks callbacks;

  public List<Proxy> getProxies(URI uri) {
    return proxySelector.select(uri);
  }

  /**
   * Populate a server instance with the most appropriate proxy.
   * 
   * <p>The below code favors HTTP/S proxies over direct connections.
   * It ignores SOCKS proxies due to
   * Burp only supporting one SOCKS proxy at a time.
   * 
   * @param server a server instance
   * @param proxies a list of proxies or null
   */
  public void populateProxyForServer(Server server, List<Proxy> proxies) {
    // https://github.com/MarkusBernhardt/proxy-vole/tree/master#choose-the-right-proxy
    Proxy proxy = Proxy.NO_PROXY;
    if (proxies != null) {
      loop: for (Proxy p : proxies) {
        switch (p.type()) {
          case HTTP:
            proxy = p;
            break loop;
          case DIRECT:
            proxy = p;
            break;
          case SOCKS:
            proxy = p;
            break;
          // Unreachable
          default:
            break;
        }
      }
    }

    switch (proxy.type()) {
      case DIRECT:
        callbacks.printOutput(String.format("No proxy / server is directly accessible."));
        break;
      case HTTP:
        if (proxy.address() instanceof InetSocketAddress) {
          InetSocketAddress address = (InetSocketAddress) proxy.address();
          // Don't trigger a DNS lookup
          server.setEnabled(true);
          server.setProxyHost(address.getHostString());
          server.setProxyPort(address.getPort());
          callbacks.printOutput(String.format("Server '%s' is HTTP", server));
        } else {
          final String type =
              proxy.address() == null ? "null" : proxy.address().getClass().getName();
          callbacks.printError(String.format("Unsupported address type: %s", type));
        }
        // log
        break;
      case SOCKS:
        callbacks.printError(String.format("Server '%s' uses upstream SOCKS proxy, "
            + "however Burp can only support 1 upstream SOCKS proxy. Not adding!", server));
        break;
      // Unreachable  
      default:
        callbacks.printError(String.format("Unsupported proxy type: %s", proxy.type()));
        break;
    }
  }

  public boolean hasProxy(Server server) {
    return !Strings.isNullOrEmpty(server.getProxyHost());
  }
}
