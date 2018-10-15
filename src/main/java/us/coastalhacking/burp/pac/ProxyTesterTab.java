package us.coastalhacking.burp.pac;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import com.google.inject.Inject;
import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.Proxy;
import java.net.URI;
import java.text.MessageFormat;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTextField;

public class ProxyTesterTab implements ITab {
  private JButton test;
  private JTextField url;
  private JTextArea output;

  @Inject
  protected ProxyUtils proxyUtils;

  @Inject
  protected IBurpExtenderCallbacks callbacks;

  @Override
  public String getTabCaption() {
    return "PAC";
  }

  @Override
  public Component getUiComponent() {    
    GridBagConstraints c = new GridBagConstraints();
    c.fill = GridBagConstraints.HORIZONTAL;
    c.anchor = GridBagConstraints.NORTHWEST;
    c.weightx = 1.0;
    c.weighty = 0.0;

    GridBagLayout gridBag = new GridBagLayout();
    JPanel panel = new JPanel(gridBag);

    // Row 1
    JLabel urlLabel = new JLabel("URL (scheme://host[:port]) to lookup:");
    gridBag.setConstraints(urlLabel, c);
    panel.add(urlLabel);

    this.url = new JTextField(30);
    this.url.setText("https://portswigger.net");
    c.gridwidth = GridBagConstraints.RELATIVE;
    gridBag.setConstraints(url, c);
    panel.add(this.url);

    this.test = new JButton("Lookup proxy for URL");
    c.gridwidth = GridBagConstraints.REMAINDER;
    gridBag.setConstraints(test, c);

    this.test.addActionListener(new ActionListener() {

      public void actionPerformed(ActionEvent arg0) {
        URI uri;
        try {
          uri = new URI(ProxyTesterTab.this.url.getText().trim());
          List<Proxy> results = proxyUtils.getProxies(uri);
          if (results == null || results.size() == 0) {
            ProxyTesterTab.this.output.append("No proxy found.\n");
            return;
          }
          ProxyTesterTab.this.output.append(MessageFormat.format("Proxy: {0}\n", results.get(0)));
        } catch (Exception e) {
          ProxyTesterTab.this.output.append(MessageFormat.format("Error: {0}\n", e.getMessage()));
        }

      }
    });
    panel.add(this.test);

    // Row 2
    this.output = new JTextArea(5, 50);
    c.gridwidth = GridBagConstraints.REMAINDER;
    c.weighty = 1.0;
    gridBag.setConstraints(output, c);
    panel.add(output);

    return panel;
  }

}
