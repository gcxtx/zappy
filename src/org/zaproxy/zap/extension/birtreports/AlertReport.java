package org.zaproxy.zap.extension.birtreports;

import java.util.List;

import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.model.SiteNode;

public class AlertReport implements IAlertReport{
	// implement the interface to add functionality to the class and create a sample report to demonstrate the functionality of the scripted data source.
		private SiteNode site;
		private List<Alert> alerts;

		public void setSite()
		{
		       SiteMap siteMap = Model.getSingleton().getSession().getSiteTree();
		       site = (SiteNode) siteMap.getRoot();
		}

	    public AlertReport getAlertsReport()
	    {
			AlertReport report = new AlertReport();
	    	this.setSite();
			this.alerts = site.getAlerts();
			return report;
		}
		
}
