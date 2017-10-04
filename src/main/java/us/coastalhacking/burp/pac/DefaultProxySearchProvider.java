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

import com.github.markusbernhardt.proxy.ProxySearch;
import com.github.markusbernhardt.proxy.ProxySearch.Strategy;
import com.github.markusbernhardt.proxy.util.PlatformUtil;
import com.github.markusbernhardt.proxy.util.PlatformUtil.Platform;
import com.google.inject.Inject;
import com.google.inject.Provider;

public class DefaultProxySearchProvider implements Provider<ProxySearch> {

  protected ProxySearch proxySearch;
  
  @Inject
  protected PlatformUtil platformUtil;

  @Override
  public ProxySearch get() {
    if (proxySearch == null) {
      // TODO: make configurable?
      // This loads JAVA, OS, and ENV proxy settings only, headless or not
      proxySearch = new ProxySearch();
      proxySearch.addStrategy(Strategy.JAVA);
      proxySearch.addStrategy(Strategy.OS_DEFAULT);
      proxySearch.addStrategy(Strategy.ENV_VAR);
      Platform platform = PlatformUtil.getCurrentPlattform();
      if (platform == Platform.WIN) {
        proxySearch.addStrategy(Strategy.IE);
      }
    }
    return proxySearch;
  }

}
