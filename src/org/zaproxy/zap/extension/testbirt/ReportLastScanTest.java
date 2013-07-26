package org.zaproxy.zap.extension.testbirt;

import static org.junit.Assert.*;

import java.io.File;
import java.util.ResourceBundle;
import org.zaproxy.zap.extension.birtreports.*;
import org.junit.Test;

public class ReportLastScanTest {

	private ResourceBundle messages = null;
	
	@Test
	public void testGenerateXml() {
		
		ReportLastScan reportgen = new ReportLastScan(); 
		//generate xml file with the case when there is no alerts yet created i.e., Model=null
		File birtfile = new File("reportdesignfiles/xmloutput/xmloutputzap.xml");
		File report= new File("");
		try {
			report = reportgen.generate(birtfile.getAbsolutePath(), null, "xml/report.xml.xsl");
		} catch (Exception e) {
			assertTrue("There are no alerts generated yet.", !report.exists());
		}
	}

	@Test
	public void testIfXmlOutputExists()
	{
		//This method tests if the XML output file is missing
		File xmloutput = new File("reportdesignfiles/xmloutput/xmloutputzap.xml");
		assertTrue("The xml output file is missing.", !xmloutput.exists());
	}
	
	@Test
	public void testIfBirtDesignExists()
	{
		//This method tests if the BIRT rpt file exists
		File birtdesign = new File("reportdesignfiles/AlertsOwaspZap.rptdesign");
		assertTrue("There is no BIRT report design.", !birtdesign.exists());
	}
	
	@Test
	public void testGenerateXmlforBirtPdf() {
		fail("Not yet implemented");
	
	}

	@Test
	public void testExecuteBirtPdfReport() {
		fail("Not yet implemented");
	}

	@Test
	public void testOpenPDF() {
		// test the filename is empty
		File file = new File("");
		assertTrue("PDF cannot be opened. File does not exist.", !file.exists());
	}

}
