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

import burp.IHttpService;
import java.net.URI;
import us.coastalhacking.burp.pac.config.Server;

public class Adapter {

  /**
   * Convert an IHttpService instance into a URI instance.
   * 
   * @param httpService An IHttpService instance
   * @return a URI instance
   */
  public URI toUri(IHttpService httpService) {
    try {
      return new URI(httpService.getProtocol(), null, httpService.getHost(), httpService.getPort(),
          null, null, null);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Convert an IHttpService instance into a Server instance.
   * 
   * @param httpService an IHttpService instance
   * @return a server instance
   */
  public Server toServer(IHttpService httpService) {
    Server server = new Server();
    server.setDestinationHost(httpService.getHost());
    return server;
  }

}
