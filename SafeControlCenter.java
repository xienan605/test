package com.insigma.odin.framework.safe;

import java.io.FileInputStream;
import java.io.InputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;

import com.insigma.odin.framework.safe.license.License;
import com.insigma.odin.framework.safe.license.LicenseManager;
import com.insigma.odin.framework.safe.util.SafeConst;
import com.insigma.odin.framework.safe.validate.AppcontextValidate;
import com.insigma.odin.framework.safe.validate.AppserverValidate;
import com.insigma.odin.framework.safe.validate.CPUSValidate;
import com.insigma.odin.framework.safe.validate.DatabaseTableValidate;
import com.insigma.odin.framework.safe.validate.ExpirationValidate;
import com.insigma.odin.framework.safe.validate.IValidate;
import com.insigma.odin.framework.safe.validate.IpValidate;
import com.insigma.odin.framework.safe.validate.LogincountValidate;
import com.insigma.odin.framework.safe.validate.MacValidate;
import com.insigma.odin.framework.safe.validate.OpsystemValidate;
import com.insigma.odin.framework.safe.validate.ResourcesValidate;
import com.insigma.odin.framework.safe.validate.SessionsValidate;
import com.insigma.odin.framework.safe.validate.SignatureValidate;
import com.insigma.odin.framework.safe.validate.UnitsCountValidate;
import com.insigma.odin.framework.safe.validate.UnitsUnitsidValidate;
import com.insigma.odin.framework.safe.validate.ValidateThread;


/**
 * ��ȫ���ƴ�������
 * <p>Title: ����</p>
 * @author jinwei
 * @date 2010-2-26
 * <p>Company: �㽭���¶���������޹�˾</p>
 *
 */
public class SafeControlCenter {
	
	/**
	 * ��¼��־
	 */
	private static Logger log = Logger.getLogger(SafeControlCenter.class);
	
	/**
	 * �������浱ǰ��servlet�����ģ�ͨ����һ���Ի�ȡservlet�������������Ի�ȡ·����Ϣ
	 */
	private static ServletContext servletContext = null;
	
	private static SafeControlCenter scc;
	
	/**
	 * ��֤�̶߳�����Ҫ����Թ���ʱ�����֤
	 */
	private ValidateThread validateThread;
	/**
	 * ��¼��ǰ��Ʒ
	 */
	private String cueProduct;
	
	/**
	 * ��¼��ǰӦ�ø�Ŀ¼��������web���������Ŀ¼
	 */
	private String rootDir = null;
	
	/**
	 * �Ƿ��Ѿ�ͨ����ǩ����֤
	 */
	private boolean validateSignSucc = false;
	
	/**
	 * �Ƿ���Ҫ���ӳٴ���
	 */
	private boolean isDoDelay = false;
	
	public boolean isDoDelay() {
		return isDoDelay;
	}

	public void setDoDelay(boolean isDoDelay) {
		this.isDoDelay = isDoDelay;
	}

	private SafeControlCenter(){}
	
	/**
	 * ��ȡ��ȫ���ƴ�������ʵ������
	 * @return
	 */
	public static SafeControlCenter getInstance(){
		if(scc==null){
			scc = new SafeControlCenter();
			scc.validateThread = new ValidateThread();
		}
		return scc;
	}
	
	public static SafeControlCenter getInstance(String product){
		if(scc==null){
			scc = new SafeControlCenter();
			scc.validateThread = new ValidateThread();
		}
		scc.setCueProduct(product);
		return scc;
	}
	
	/**
	 * ������֤���ͽ�����֤ ��Ŀǰֻ������֤������·����
	 * @param request �������
	 * @param validateType  ��֤���ͣ���cups������Сд��������дת����ӡ�Validate����������֤��"CPUSValidate"
	 * @param component �����
	 * @return
	 */
	public boolean safeValidate(HttpServletRequest request,String validateType,String component){
		boolean rtn = false;
		try{
			if(beforeValidateAccess()){
				IValidate validate = this.getIValidate(validateType);
				if(validateType.toLowerCase().equals(SafeConst.VT_APPCONTEXT)){
					rtn = validate.validate(request.getContextPath(), component);
				}
			}
		}catch(SysSafeException e){
			this.error(e);
		}
		if(!rtn){
			this.doValidateFail();
		}
		return rtn;
	}
	/**
	 * ������֤���ͽ�����֤
	 * @param validateType ��֤���ͣ���cups������Сд��������дת����ӡ�Validate����������֤��"CPUSValidate"
	 * @param validateContent �ȴ���֤��������
	 * @param component  �����
	 * @return true ��֤ͨ������֤��ͨ��
	 */
	/*
	public boolean safeValidate(String validateType,Object validateContent,String component){
		return true;
	}
	*/
	/**
	 * ������֤���ͽ�����֤
	 * @param validateType ��֤����
	 * @param component  �����
	 * @return
	 */
	public boolean safeValidate(String validateType,String component){
		boolean rtn = false;
		try{
			if(beforeValidateAccess()){
				IValidate validate = this.getIValidate(validateType);
				boolean isValSign = false;
				if(validateType.toLowerCase().equals(SafeConst.VT_EXPIRATION)){
					rtn = true;
					if(!validateThread.isAlive()){
						validateThread.setComponentName(component);
						validateThread.start();
					}
				}else if(validateType.toLowerCase().equals(SafeConst.VT_APPSERVER)){
					rtn = validate.validate(this.getIValidateContExecute().getAppserver(), component);
				}else if(validateType.toLowerCase().equals(SafeConst.VT_IP)){
					rtn = validate.validate(this.getIValidateContExecute().getIp(), component);
				}else if(validateType.toLowerCase().equals(SafeConst.VT_MAC)){
					rtn = validate.validate(this.getIValidateContExecute().getMac(), component);
				}else if(validateType.toLowerCase().equals(SafeConst.VT_CPUS)){
					rtn = validate.validate(this.getIValidateContExecute().getCPUS(), component);
				}else if(validateType.toLowerCase().equals(SafeConst.VT_RESOURCES)){
					rtn = validate.validate(null, component);
				}else if(validateType.toLowerCase().equals(SafeConst.VT_OPSYSTEM)){
					rtn = validate.validate(this.getIValidateContExecute().getOpSystem(), component);
				}else if(validateType.toLowerCase().equals(SafeConst.VT_DATABASE)){
					rtn = validate.validate(null, component);
				}else if(validateType.toLowerCase().equals(SafeConst.VT_SIGNATURE)){
					isValSign = true;
					rtn = validate.validate(null, component);
					validateSignSucc = rtn;
				}else if(validateType.toLowerCase().equals(SafeConst.VT_SESSIONS)){
					rtn = validate.validate(this.getIValidateContExecute().getSessCount(), component);
				}else if(validateType.toLowerCase().equals(SafeConst.VT_LOGINCOUNT)){
					rtn = validate.validate(this.getIValidateContExecute().getLoginCount(), component);
				}
				if(rtn && !isValSign){
					rtn = afterValidateAccess(component);
				}
			}
		}catch(SysSafeException e){
			this.error(e);
			this.doValidateFail();
		}
		if(!rtn){
			this.doValidateFail();
		}
		return rtn;
	}
	
	/**
	 * ��ȡ��֤�����������࣬ͨ��������ȡ�õ�ǰ��������
	 * @return
	 */
	public IValidateContExecute getIValidateContExecute(){
		return new ValidateContExecute();
	}
	
	/**
	 * ������֤���ͻ�ȡ������֤��
	 * @param validateType
	 * @return
	 */
	public IValidate getIValidate(String validateType){
		if(validateType.toLowerCase().equals(SafeConst.VT_CPUS)){
			return new CPUSValidate();
		}else if(validateType.toLowerCase().equals(SafeConst.VT_EXPIRATION)){
			return new ExpirationValidate();
		}else if(validateType.toLowerCase().equals(SafeConst.VT_APPSERVER)){
			return new AppserverValidate();
		}else if(validateType.toLowerCase().equals(SafeConst.VT_IP)){
			return new IpValidate();
		}else if(validateType.toLowerCase().equals(SafeConst.VT_MAC)){
			return new MacValidate();
		}else if(validateType.toLowerCase().equals(SafeConst.VT_RESOURCES)){
			return new ResourcesValidate();
		}else if(validateType.toLowerCase().equals(SafeConst.VT_UNITSCOUNT)){
			return new UnitsCountValidate();
		}else if(validateType.toLowerCase().equals(SafeConst.VT_UNITSID)){
			return new UnitsUnitsidValidate();
		}else if(validateType.toLowerCase().equals(SafeConst.VT_APPCONTEXT)){
			return new AppcontextValidate();
		}else if(validateType.toLowerCase().equals(SafeConst.VT_DATABASE)){
			return new DatabaseTableValidate();
		}else if(validateType.toLowerCase().equals(SafeConst.VT_SIGNATURE)){
			return new SignatureValidate();
		}else if(validateType.toLowerCase().equals(SafeConst.VT_OPSYSTEM)){
			return new OpsystemValidate();
		}else if(validateType.toLowerCase().equals(SafeConst.VT_SESSIONS)){
			return new SessionsValidate();
		}else if(validateType.toLowerCase().equals(SafeConst.VT_LOGINCOUNT)){
			return new LogincountValidate();
		}
		return null;
	}
	/**
	 * ��֤֮ǰ�Ĺ���������
	 * @throws SysSafeException 
	 */
	@SuppressWarnings("static-access")
	private boolean beforeValidateAccess() throws SysSafeException{
		boolean rtn = false;
		try{
			LicenseManager lm = LicenseManager.getInstance();
			List<License> list = lm.getLicensesGroup();
			if(list==null || list.size()==0){
				//String path = getLicenseFilePath();
				/*if(this.getServletContext()==null){
					InputStream is = new FileInputStream(SafeConst.CORE_CONFIG_PATH);
					lm.setLicensesGroup(lm.getILicenseParse().parse(is,this.getCueProduct()));
				}else{
					lm.setLicensesGroup(lm.getILicenseParse().parse(this.getServletContext().getResourceAsStream(SafeConst.CORE_CONFIG_PATH),this.getCueProduct()));
				}*/
				InputStream is = this.getClass().getClassLoader().getResourceAsStream("coreConfig.xml");
				lm.setLicensesGroup(lm.getILicenseParse().parse(is,this.getCueProduct()));
				rtn = true;
			}else{
				rtn = true;
			}
		}catch(Exception e){
			if(e instanceof SysSafeException){
				throw (SysSafeException)e;
			}
			e.printStackTrace();
		}
		return rtn;
	}
	/**
	 * ��֤֮�����ش���
	 * @param component
	 * @return
	 * @throws SysSafeException
	 */
	private boolean afterValidateAccess(String component) throws SysSafeException{
		boolean rtn = true;
		if(!this.validateSignSucc){
			rtn = safeValidate("signature", component);
		}
		return rtn;
	}
	
	/*
	@SuppressWarnings("static-access")
	private String getLicenseFilePath(){
		String path = null;
		if(this.getServletContext()!=null){
			this.setRootDir(this.getServletContext().getRealPath("/"));
			path = this.getRootDir() + "/WEB-INF/conf/license.xml";
		}else if(this.getRootDir()==null){
			path = this.getClass().getResource("/").getPath();
			path = path.substring(0, path.length()-"classes/".length());
			path += "conf"+System.getProperty("file.separator") + "license.xml";
		}
		log.info(path);
		return path;
	}
	*/
	/**
	 * ��ȡ��Ŀ¼
	 * @return
	 */
	public String getRootDir() {
		return rootDir;
	}
    /**
     * ���ø�Ŀ¼
     * @param rootDir
     */
	public void setRootDir(String rootDir) {
		this.rootDir = rootDir;
	}

	/**
	 * ��ϵͳ��������ʱ����˵����֤��ͨ����ͨ���˷�����ӡ������Ϣ
	 * @param e
	 */
	public void error(Exception e){
		Date now = new Date();
		SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
		System.out.println(format.format(now)+"��"+e.getMessage());
		String signError = "Core config file sign error,validate fail��";
		if(e.getMessage().indexOf(signError)>0){ //ǩ����Ĵ�����������ҵ���ǿ������Զ��˳�����
			System.exit(0);
		}
	}
	/**
	 * ��֤ʧ�ܻ���֤ʱ�����쳣ʱ�Ĵ���
	 * <p>ʱ�䣺 2013-4-16</p>
	 */
	public void doValidateFail(){
//		License lic  = LicenseManager.getInstance().getCueCoreConfig();
//		if(lic==null || "RELEASE,TEST".indexOf(lic.getType())<0){ //DEVELOPΪ�������ã�TESTΪ�������ã�RELEASEΪ�������ã���������Զ�ֹͣ�����������ȡ�ӳ�����
//			System.exit(0);
//		}else{
//			this.isDoDelay = true;
//		}
//		this.isDoDelay = false;  //����������Ժ��������ö�������ڣ����ȫ�������ӳ�
//		System.exit(0);
	}
	/**
	 * �ǿ��������������ɣ������ӳٷ�ʽ
	 * ��������ϵͳ����
	 * @author jinw
	 */
	@SuppressWarnings("static-access")
	public void doDelay(){
		try {
			//this.isDoDelay = true; //�����Ƿ�����ȷ�ӳ���
			//�õ�ǰ�߳��Զ��ӳ�5��
			if(this.isDoDelay){
				License license = LicenseManager.getInstance().getLicenseByComponentName(SafeConst.PDT_INSIIS_COMP_ODIN);
				int delay = Integer.parseInt((String) license.getExtendInfo().get("delay"));
				if(delay==0){
					System.exit(0);
				}else{
					Thread.currentThread().sleep(delay);
				}
			}
		} catch (InterruptedException e) {
			e.printStackTrace();
		} catch (SysSafeException e) {
			System.out.println("�Ҳ���ϵͳ���������ļ��������Զ���ֹ��");
			System.exit(0);
		}
	}
	
	public static ServletContext getServletContext() {
		return servletContext;
	}

	public static void setServletContext(ServletContext servletContext) {
		SafeControlCenter.servletContext = servletContext;
	}

	/*
	public static void main(String[] args) throws SysSafeException{
		SafeControlCenter scc = new SafeControlCenter();
		System.out.println(scc.getClass().getResource("/").getPath());
		System.out.println(scc.getIValidateContExecute().getCPUS());
		System.out.println(scc.getIValidateContExecute().getIp());
		System.out.println(scc.getIValidateContExecute().getOpSystem());
	}
	*/
	public String getCueProduct() {
		return cueProduct;
	}

	public void setCueProduct(String cueProduct) {
		this.cueProduct = cueProduct;
	}
	
}
