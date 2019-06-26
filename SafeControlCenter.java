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
 * 安全控制处理中心
 * <p>Title: 核三</p>
 * @author jinwei
 * @date 2010-2-26
 * <p>Company: 浙江网新恩普软件有限公司</p>
 *
 */
public class SafeControlCenter {
	
	/**
	 * 记录日志
	 */
	private static Logger log = Logger.getLogger(SafeControlCenter.class);
	
	/**
	 * 用来缓存当前的servlet上下文，通过其一可以获取servlet容器名，二可以获取路径信息
	 */
	private static ServletContext servletContext = null;
	
	private static SafeControlCenter scc;
	
	/**
	 * 验证线程对象，主要负责对过期时间的验证
	 */
	private ValidateThread validateThread;
	/**
	 * 记录当前产品
	 */
	private String cueProduct;
	
	/**
	 * 记录当前应用根目录，即就是web里的上下文目录
	 */
	private String rootDir = null;
	
	/**
	 * 是否已经通过了签名验证
	 */
	private boolean validateSignSucc = false;
	
	/**
	 * 是否需要做延迟处理
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
	 * 获取安全控制处理中心实例对象
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
	 * 根据验证类型进行验证 【目前只用来验证上下文路径】
	 * @param request 请求对象
	 * @param validateType  验证类型，如cups，必须小写，经过大写转换后加“Validate”必须是验证类"CPUSValidate"
	 * @param component 组件名
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
	 * 根据验证类型进行验证
	 * @param validateType 验证类型，如cups，必须小写，经过大写转换后加“Validate”必须是验证类"CPUSValidate"
	 * @param validateContent 等待验证的内容项
	 * @param component  组件名
	 * @return true 验证通过，验证不通过
	 */
	/*
	public boolean safeValidate(String validateType,Object validateContent,String component){
		return true;
	}
	*/
	/**
	 * 根据验证类型进行验证
	 * @param validateType 验证类型
	 * @param component  组件名
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
	 * 获取验证内容生成器类，通过该类能取得当前服务器所
	 * @return
	 */
	public IValidateContExecute getIValidateContExecute(){
		return new ValidateContExecute();
	}
	
	/**
	 * 根据验证类型获取具体验证类
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
	 * 验证之前的公共处理方法
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
	 * 验证之后的相关处理
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
	 * 获取根目录
	 * @return
	 */
	public String getRootDir() {
		return rootDir;
	}
    /**
     * 设置根目录
     * @param rootDir
     */
	public void setRootDir(String rootDir) {
		this.rootDir = rootDir;
	}

	/**
	 * 当系统发生错误时或者说是验证不通过是通过此方法打印出错信息
	 * @param e
	 */
	public void error(Exception e){
		Date now = new Date();
		SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
		System.out.println(format.format(now)+"："+e.getMessage());
		String signError = "Core config file sign error,validate fail！";
		if(e.getMessage().indexOf(signError)>0){ //签名类的错误则无论商业还是开发都自动退出服务
			System.exit(0);
		}
	}
	/**
	 * 验证失败或验证时出现异常时的处理
	 * <p>时间： 2013-4-16</p>
	 */
	public void doValidateFail(){
//		License lic  = LicenseManager.getInstance().getCueCoreConfig();
//		if(lic==null || "RELEASE,TEST".indexOf(lic.getType())<0){ //DEVELOP为开发配置，TEST为测试配置，RELEASE为生产配置，开发许可自动停止服务，其它则采取延迟做法
//			System.exit(0);
//		}else{
//			this.isDoDelay = true;
//		}
//		this.isDoDelay = false;  //新需求里测试和生产配置都不会过期，因此全部不用延迟
//		System.exit(0);
	}
	/**
	 * 非开发或测试类型许可，采用延迟方式
	 * 即让整个系统变慢
	 * @author jinw
	 */
	@SuppressWarnings("static-access")
	public void doDelay(){
		try {
			//this.isDoDelay = true; //测试是否能正确延迟用
			//让当前线程自动延迟5秒
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
			System.out.println("找不到系统核心配置文件！服务将自动终止。");
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
