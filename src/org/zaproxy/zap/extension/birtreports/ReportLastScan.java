/*
 *
 * Paros and its related class files.
 * 
 * Paros is an HTTP/HTTPS proxy for assessing web application security.
 * Copyright (C) 2003-2004 Chinotec Technologies Company
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the Clarified Artistic License
 * as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Clarified Artistic License for more details.
 * 
 * You should have received a copy of the Clarified Artistic License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
// ZAP: 2011/10/01 Fixed filename problem (issue 161)
// ZAP: 2012/01/24 Changed outer XML (issue 268) c/o Alla
// ZAP: 2012/03/15 Changed the methods getAlertXML and generate to use the class 
// StringBuilder instead of StringBuffer.
// ZAP: 2012/04/25 Added @Override annotation to all appropriate methods.
// ZAP: 2013/03/03 Issue 546: Remove all template Javadoc comments

package org.zaproxy.zap.extension.birtreports;

import edu.stanford.ejalbert.BrowserLauncher;

import java.awt.Desktop;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.imageio.ImageIO;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileFilter;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.extension.report.ReportGenerator;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.XmlReporterExtension;
import org.zaproxy.zap.utils.XMLStringUtil;
import org.zaproxy.zap.view.ScanPanel;
//birt jars
import org.eclipse.birt.core.exception.BirtException;
import org.eclipse.birt.core.framework.Platform;
import org.eclipse.birt.report.engine.api.EngineConfig;
import org.eclipse.birt.report.engine.api.EngineException;
import org.eclipse.birt.report.engine.api.IReportRunnable;
import org.eclipse.birt.report.engine.api.IRunAndRenderTask;
import org.eclipse.birt.report.engine.api.PDFRenderOption;
import org.eclipse.birt.report.engine.api.impl.ReportEngine;

public class ReportLastScan {

    private Logger logger = Logger.getLogger(ReportLastScan.class);
    private ResourceBundle messages = null;
    private static String fileNameLogo="";
    public ReportLastScan() {
    }


    public void uploadLogo (ViewDelegate view)
    {
        try {
            JFileChooser chooser = new JFileChooser(Model.getSingleton().getOptionsParam().getUserDirectory());
            chooser.setFileFilter(new FileFilter() {

                @Override
                public boolean accept(File file) {
                    if (file.isDirectory()) {
                        return true;
                    } else if (file.isFile()
                            && file.getName().toLowerCase().endsWith(".jpg")) {
                        return true;
                    }
                    return false;
                }

                @Override
                public String getDescription() {
                    return ".jpg";
                }
            });

            File file = null;
            
            int rc = chooser.showSaveDialog(View.getSingleton().getMainFrame());
            if (rc == JFileChooser.APPROVE_OPTION) {
                file = chooser.getSelectedFile();
                if (file != null) {
                    Model.getSingleton().getOptionsParam().setUserDirectory(chooser.getCurrentDirectory());
                    fileNameLogo = file.getAbsolutePath().toLowerCase();
                    if (!fileNameLogo.endsWith(".jpg")) {
                        file = new File(file.getAbsolutePath() + ".jpg"); 
                        fileNameLogo = file.getAbsolutePath();
                    } // select the file and close the Save dialog box
                    
                    //Save the image with the name logo.jpg
                    BufferedImage image = null;
                    try {
             
                        image = ImageIO.read(new File(fileNameLogo));
                        File logo = new File("reportdesignfiles/logo.jpg");
                        ImageIO.write(image, "jpg", logo);
                        fileNameLogo = logo.getAbsolutePath().substring(0,logo.getAbsolutePath().lastIndexOf(File.separator));
             
                    } catch (IOException e) {
                    	e.printStackTrace();
                    }
                }
            }

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            //view.showWarningDialog(Constant.messages.getString("report.unexpected.warning"));
        }
    }
    
    public File generate(String fileName, Model model, String xslFile) throws Exception {

    	StringBuilder sb = new StringBuilder(500);
        // ZAP: Dont require scan to have been run

        sb.append("<?xml version=\"1.0\"?>");
        sb.append("<OWASPZAPReport version=\"").append(Constant.PROGRAM_VERSION).append("\" generated=\"").append(ReportGenerator.getCurrentDateTimeString()).append("\">\r\n");
        // sb.append(getAlertXML(model.getDb(), null));
        sb.append(siteXML());
        sb.append("</OWASPZAPReport>");

        File report = ReportGenerator.stringToHtml(sb.toString(), xslFile, fileName);

        return report;
    }

    private StringBuilder siteXML() {
        StringBuilder report = new StringBuilder();
        SiteMap siteMap = Model.getSingleton().getSession().getSiteTree();
        SiteNode root = (SiteNode) siteMap.getRoot();
        int siteNumber = root.getChildCount();
        for (int i = 0; i < siteNumber; i++) {
            SiteNode site = (SiteNode) root.getChildAt(i);
            String siteName = ScanPanel.cleanSiteName(site, true);
            String[] hostAndPort = siteName.split(":");
            boolean isSSL = (site.getNodeName().startsWith("https"));
            String siteStart = "<site name=\"" + XMLStringUtil.escapeControlChrs(site.getNodeName()) + "\"" +
                    " host=\"" + XMLStringUtil.escapeControlChrs(hostAndPort[0])+ "\""+
                    " port=\"" + XMLStringUtil.escapeControlChrs(hostAndPort[1])+ "\""+
                    " ssl=\"" + String.valueOf(isSSL) + "\"" +
                    ">";
            StringBuilder extensionsXML = getExtensionsXML(site);
            String siteEnd = "</site>";
            report.append(siteStart);
            report.append(extensionsXML);
            report.append(siteEnd);
        }
        return report;
    }
    
    public StringBuilder getExtensionsXML(SiteNode site) {
        StringBuilder extensionXml = new StringBuilder();
        ExtensionLoader loader = Control.getSingleton().getExtensionLoader();
        int extensionCount = loader.getExtensionCount();
        for(int i=0; i<extensionCount; i++) {
            Extension extension = loader.getExtension(i);
            if(extension instanceof XmlReporterExtension) {
                extensionXml.append(((XmlReporterExtension)extension).getXml(site));
            }
        }
        return extensionXml;
    }


    public void generateXml(ViewDelegate view, Model model) {

        // ZAP: Allow scan report file name to be specified
        try {
            JFileChooser chooser = new JFileChooser(Model.getSingleton().getOptionsParam().getUserDirectory());
            chooser.setFileFilter(new FileFilter() {

                @Override
                public boolean accept(File file) {
                    if (file.isDirectory()) {
                        return true;
                    } else if (file.isFile()
                            && file.getName().toLowerCase().endsWith(".xml")) {
                        return true;
                    }
                    return false;
                }

                @Override
                public String getDescription() {
                    return Constant.messages.getString("file.format.xml");
                }
            });

            File file = null;
            int rc = chooser.showSaveDialog(View.getSingleton().getMainFrame());
            if (rc == JFileChooser.APPROVE_OPTION) {
                file = chooser.getSelectedFile();
                if (file != null) {
                    Model.getSingleton().getOptionsParam().setUserDirectory(chooser.getCurrentDirectory());
                    String fileNameLc = file.getAbsolutePath().toLowerCase();
                    if (!fileNameLc.endsWith(".xml")) {
                        file = new File(file.getAbsolutePath() + ".xml");
                    }
                }

                if (!file.getParentFile().canWrite()) {
                    view.showMessageDialog(
                            MessageFormat.format(Constant.messages.getString("report.write.error"),
                            new Object[]{file.getAbsolutePath()}));
                    return;
                }

                File report = generate(file.getAbsolutePath(), model, "xml/report.xml.xsl");
                if (report == null) {
                    view.showMessageDialog(
                            MessageFormat.format(Constant.messages.getString("report.unknown.error"),
                            new Object[]{file.getAbsolutePath()}));
                    return;
                }

                try {
                    BrowserLauncher bl = new BrowserLauncher();
                    bl.openURLinBrowser("file://" + report.getAbsolutePath());
                } catch (Exception e) {
                    logger.error(e.getMessage(), e);
                    view.showMessageDialog(
                            MessageFormat.format(Constant.messages.getString("report.complete.warning"),
                            new Object[]{report.getAbsolutePath()}));
                }
            }

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            view.showWarningDialog(Constant.messages.getString("report.unexpected.warning"));
        }
    }

    public void generateXmlforBirtPdf(ViewDelegate view, Model model)
    {
    	try
    	{
    		//generate xml file
    		File birtfile = new File("reportdesignfiles/xmloutput/xmloutputzap.xml");
    		File report = generate(birtfile.getAbsolutePath(), model, "xml/report.xml.xsl");
    		 if (report == null) {
                 view.showMessageDialog(
                         MessageFormat.format(Constant.messages.getString("report.unknown.error"),
                         new Object[]{birtfile.getAbsolutePath()}));
                 return;                 
               
             }
    		}
    		catch(Exception e)
    		{
    		 logger.error(e.getMessage(), e);
             view.showWarningDialog(Constant.messages.getString("report.unexpected.warning"));
    		
    		 }
    	
    	
    	
    }
    public void executeBirtPdfReport(ViewDelegate view,String reportDesign)
	{
		try {
						
			//user chooses where to save PDF report
			JFileChooser chooser = new JFileChooser(Model.getSingleton().getOptionsParam().getUserDirectory());
            chooser.setFileFilter(new FileFilter() {

                @Override
                public boolean accept(File file) {
                    if (file.isDirectory()) {
                        return true;
                    } else if (file.isFile()
                            && file.getName().toLowerCase().endsWith(".pdf")) {
                        return true;
                    }
                    return false;
                }

                @Override
                public String getDescription() {
                    return Constant.messages.getString("file.format.pdf");
                    //TODO: define message on package Messages.Properties own file
                	//return messages.getString("file.format.pdf");
                }
            });

            File file = null;
            int rc = chooser.showSaveDialog(View.getSingleton().getMainFrame());
            if (rc == JFileChooser.APPROVE_OPTION) {
                file = chooser.getSelectedFile();
            }
                if (file != null) {
                    Model.getSingleton().getOptionsParam().setUserDirectory(chooser.getCurrentDirectory());
                    String fileNameLc = file.getAbsolutePath().toLowerCase();
                    // if a user forgets to specify .pdf at the end of the filename 
                    // then append it with the file name
                    if (!fileNameLc.endsWith(".pdf")) {
                        file = new File(file.getAbsolutePath() + ".pdf"); 
                        fileNameLc = file.getAbsolutePath();
                    } // select the file and close the Save dialog box
                        
                        //BIRT engine code
                        EngineConfig config = new EngineConfig();
                        config.setResourcePath(fileNameLogo);
            			Platform.startup(config);
            			
            			ReportEngine engine = new ReportEngine(config);
            			
            			IReportRunnable reportRunnable = engine.openReportDesign(reportDesign);
            			IRunAndRenderTask runAndRender = engine.createRunAndRenderTask(reportRunnable);
            			
            			PDFRenderOption option = new PDFRenderOption();
                        option.setOutputFileName(fileNameLc); // takes old file name but now I did some modification
                       
            			option.setOutputFormat("PDF");
            			runAndRender.setRenderOption(option);            			
            			runAndRender.run();            			
            			runAndRender.close();
            			// open the PDF
            			openPDF(new File(fileNameLc));
            			//engine.destroy();
            			//Platform.shutdown();
                    
                //}
//
               			
            }
				}catch (EngineException e) {
					e.printStackTrace();
					} catch (BirtException e) {
						e.printStackTrace();
						}
		
		//
	
			}
    //end
    public boolean openPDF(File file)
    {
/*        try
        {
            if (OSDetector.isWindows())
            {
                Runtime.getRuntime().exec(new String[]
                {"rundll32 url.dll,FileProtocolHandler",
                 file.getAbsolutePath()});
                return true;
            } else if (OSDetector.isLinux() || OSDetector.isMac())
            {
                Runtime.getRuntime().exec(new String[]{"/usr/bin/open",
                                                       file.getAbsolutePath()});
                return true;
            } else
            {
                // Unknown OS, try with desktop
                if (Desktop.isDesktopSupported())
                {
                    Desktop.getDesktop().open(file);
                    return true;
                }
                else
                {
                    return false;
                }
            }
        } catch (Exception e)
        {
            e.printStackTrace(System.err);
            return false;
        }*/
    	
    	if (Desktop.isDesktopSupported()) {
    	    try {
    	        //File myFile = new File("/path/to/file.pdf");
    	        Desktop.getDesktop().open(file);
    	    } catch (IOException ex) {
    	        // no application registered for PDFs
    	    	return false;
    	    }
    	}
    	return true;
    }
    
    public static class OSDetector
    {
        private static boolean isWindows = false;
        private static boolean isLinux = false;
        private static boolean isMac = false;

        static
        {
            String os = System.getProperty("os.name").toLowerCase();
            isWindows = os.contains("win");
            isLinux = os.contains("nux") || os.contains("nix");
            isMac = os.contains("mac");
        }

        public static boolean isWindows() { return isWindows; }
        public static boolean isLinux() { return isLinux; }
        public static boolean isMac() { return isMac; };

    }
    
}


