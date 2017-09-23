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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import burp.IHttpService;
import java.net.URI;
import org.junit.Test;
import us.coastalhacking.burp.pac.config.Server;

public class AdapterTest {

  @Test
  public void shouldAdapterServer() {
    IHttpService httpService = mock(IHttpService.class);
    String expectedDestinationHost = "a.b.c";
    when(httpService.getHost()).thenReturn(expectedDestinationHost);

    Adapter adapter = new Adapter();
    Server actual = adapter.toServer(httpService);
    assertEquals(expectedDestinationHost, actual.getDestinationHost());
  }

  @Test
  public void shouldAdapterUri() {
    IHttpService httpService = mock(IHttpService.class);
    String expectedHost = "a.b.c";
    int expectedPort = 1234;
    String expectedProtocol = "https";
    when(httpService.getHost()).thenReturn(expectedHost);
    when(httpService.getPort()).thenReturn(expectedPort);
    when(httpService.getProtocol()).thenReturn(expectedProtocol);

    Adapter adapter = new Adapter();
    URI actual = adapter.toUri(httpService);
    assertEquals(expectedHost, actual.getHost());
    assertEquals(expectedPort, actual.getPort());
    assertEquals(expectedProtocol, actual.getScheme());
  }

  @Test(expected = RuntimeException.class)
  public void testInvalidUri() {
    IHttpService httpService = mock(IHttpService.class);
    when(httpService.getHost()).thenReturn("123.456.789.012");
    Adapter adapter = new Adapter();
    adapter.toUri(httpService);
  }
}
