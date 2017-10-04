package us.coastalhacking.burp.pac;

import static org.junit.Assert.*;

import com.github.markusbernhardt.proxy.ProxySearch;
import com.github.markusbernhardt.proxy.search.browser.ie.IEProxySearchStrategy;
import com.github.markusbernhardt.proxy.search.desktop.DesktopProxySearchStrategy;
import com.github.markusbernhardt.proxy.search.env.EnvProxySearchStrategy;
import com.github.markusbernhardt.proxy.search.java.JavaProxySearchStrategy;
import com.github.markusbernhardt.proxy.util.PlatformUtil;
import com.github.markusbernhardt.proxy.util.PlatformUtil.Platform;
import com.google.inject.Injector;
import com.google.inject.Provider;
import org.junit.Test;

public class ProxySearchProviderTest {

  @Test
  public void shouldContainExpectedStrategies() {
    Injector injector =
        TestUtils.createInjector();
    Provider<ProxySearch> proxySearchProvider = injector.getProvider(ProxySearch.class);
    ProxySearch proxySearch = proxySearchProvider.get();
    // won't run on travis
    if (PlatformUtil.getCurrentPlattform() == Platform.WIN) {
      assertTrue(proxySearch.toString().contains(IEProxySearchStrategy.class.getName()));
    }
    assertTrue(proxySearch.toString().contains(EnvProxySearchStrategy.class.getName()));
    assertTrue(proxySearch.toString().contains(JavaProxySearchStrategy.class.getName()));
    assertTrue(proxySearch.toString().contains(DesktopProxySearchStrategy.class.getName()));
  }
  
}
