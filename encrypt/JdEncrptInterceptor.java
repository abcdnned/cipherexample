package cn.cccb.appsource.interceptor;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.apache.struts2.ServletActionContext;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import cn.cccb.appsource.jd.util.AlgorithmUtil;
import cn.cccb.appsource.jd.util.SortUtil;
import cn.cccb.epower.core.PubDataCom;
import cn.cccb.epower.core.SuperAction;
import cn.cccb.epower.util.EpUtil;

import com.alibaba.fastjson.JSONObject;
import com.opensymphony.xwork2.ActionInvocation;
import com.opensymphony.xwork2.interceptor.AbstractInterceptor;
import com.opensymphony.xwork2.interceptor.PreResultListener;

/**
 * 京东接口请求解密和验签<p>
 * @author zhangxl
 * @since 2019-03-21
 */
@SuppressWarnings("serial")
public class JdEncrptInterceptor extends AbstractInterceptor {
	protected static String publicKey1 ;
	protected static String privateKey2 ;
	protected static String clientCode;
	protected static String channelType;
	
	public JdEncrptInterceptor() {
		super();
		if( EpUtil.isNullString(channelType) ){
			JdEncrptInterceptor.publicKey1 = EpUtil.GetProperties(JdEncrptInterceptor.class.getClassLoader().getResourceAsStream("jdService.properties"), "publicKey1");
			JdEncrptInterceptor.privateKey2 = EpUtil.GetProperties(JdEncrptInterceptor.class.getClassLoader().getResourceAsStream("jdService.properties"), "privateKey2");
			JdEncrptInterceptor.clientCode = EpUtil.GetProperties(JdEncrptInterceptor.class.getClassLoader().getResourceAsStream("jdService.properties"), "clientCode");
			JdEncrptInterceptor.channelType = EpUtil.GetProperties(JdEncrptInterceptor.class.getClassLoader().getResourceAsStream("jdService.properties"), "channelType");
		}
	}

	/**
	 * log4j调试日志
	 */
	private static Logger logger = Logger.getLogger(JdEncrptInterceptor.class);
	
	@SuppressWarnings("unchecked")
	public String intercept(ActionInvocation invocation) throws Exception {
		/* 注册action监听器 处理交易返回数据 */
		invocation.addPreResultListener(new PreResultListener() {   
				public void beforeResult(ActionInvocation invocation, String arg1) {
					HttpServletResponse response = (HttpServletResponse)invocation.getInvocationContext().get(ServletActionContext.HTTP_RESPONSE);
					SuperAction action = (SuperAction) invocation.getAction();
					//返回交易结果json
					//处理返回数据
			        
			        try {
			        	//构造返回结果Json
			        	Map<String, Object> pubDataMap = action.getPubDataMap();
			        	Map<String, Object> outDataMap = action.getOutDataMap();
			        	Set<String> keys = outDataMap.keySet();
			        	Map<String,Object> resultMap = new HashMap<String,Object>();
			        	Map<String,Object> dataMap = new HashMap<String,Object>();
			        	for( String key : keys ){
			        		if( "rspCode".equals(key) ){
			        			resultMap.put("code", outDataMap.get(key) );
			        		}else if( "rspMsg".equals(key) ){
			        			resultMap.put("message", outDataMap.get(key) );
			        		}else if( "pubDataCom".equals(key) ){
			        			continue;
			        		}else{
			        			dataMap.put(key, outDataMap.get(key) );
			        		}
			        	}
			        	/*京东电子账户资金明细查询交易中data中记录中无jsonarray的key直接返回value值
			        	 * modify by zhusw  20190429
			        	 */
			        	PubDataCom pubDataCom = (PubDataCom)(pubDataMap.get("pubDataCom"));
			        	if("130012".equals(pubDataCom.getTranCode())){
			        		resultMap.put("data", outDataMap.get("acctTransList"));
			        	}else{
			        		resultMap.put("data", dataMap);
			        	}
			        	logger.debug("返回的业务数据:"+EpUtil.map2Json(resultMap));
			            //处理数据返回给Client
			            JSONObject responseEncrptJson = new JSONObject();
			            String aesRandomKey = AlgorithmUtil.getAESRandomKey();
			            String randomKeyEncrypted = AlgorithmUtil.encryptWithRSA(aesRandomKey, publicKey1);
			            String serverData = AlgorithmUtil.encryptWithAES(EpUtil.map2Json(resultMap), aesRandomKey);

			            responseEncrptJson.put("sequenceNo", pubDataMap.get("jdSequenceNo"));
			            responseEncrptJson.put("timestamp", pubDataMap.get("jdTimestamp"));
			            responseEncrptJson.put("encryptedKey", randomKeyEncrypted);
			            responseEncrptJson.put("encryptedData", serverData);

			            //签名
			            String serverSignData = AlgorithmUtil.sign(SortUtil.getNatureSortedJSONObject(responseEncrptJson).toJSONString(), privateKey2);
			            responseEncrptJson.put("signature", serverSignData);

			            logger.debug("返回的加密数据:"+responseEncrptJson.toJSONString());
			            
			            //发送post json
			            response.setCharacterEncoding("UTF-8");
			            PrintWriter printWriter = response.getWriter();
			            printWriter.write(responseEncrptJson.toJSONString());
			            printWriter.flush();
			            printWriter.close();
			        } catch (Exception e) {
			            logger.error("京东接口交易结果异常:"+e.getMessage(),e);
			        }
					
					/* 将struts2交易执行结果 r 置空  防止应用服务器报错 */
					invocation.setResultCode(null);
				}
			}
		);
		
		String r = null;
		/* 获得web容器 */
		WebApplicationContext wcx = WebApplicationContextUtils.getRequiredWebApplicationContext(ServletActionContext.getServletContext());
		HttpServletRequest request = (HttpServletRequest) invocation.getInvocationContext().get(ServletActionContext.HTTP_REQUEST);
		
		String requestJson = reqJson(request);
		logger.debug("收到json数据:"+requestJson);
		JSONObject json = JSONObject.parseObject(requestJson);
		try {
			String tranCode = request.getParameter("tranCode");
			if( EpUtil.isNullString(tranCode) ){
				throw new RuntimeException("请上送tranCode交易代码.");
			}
			
			//验证签名
			String signData = json.getString("signature");
			JSONObject orderedJo = SortUtil.getNatureSortedJSONObject(json);
			orderedJo = orderedJo.fluentRemove("signature");

			boolean sign = AlgorithmUtil.verify(orderedJo.toJSONString(), publicKey1, signData);
			if (!sign) {
			    logger.error("验证签名失败");
			    throw new Exception("验证签名失败!");
			}
			logger.info("验证签名成功");
			String randomKeyEncrypted = json.getString("encryptedKey");
	        String randomKey = null;
	        randomKey = AlgorithmUtil.decryptWithRSA(randomKeyEncrypted, privateKey2);
            String busData = AlgorithmUtil.decryptWithAES(json.getString("encryptedData"), randomKey);
            logger.info("收到的业务数据：" + busData);
            JSONObject busiJson = JSONObject.parseObject(busData);
            Map<String, Object> pubDataMap = (Map<String, Object>) wcx.getBean("pubDataMap");
            pubDataMap.put("busiData", busiJson);
            pubDataMap.put("jdSequenceNo", json.getString("sequenceNo"));
            pubDataMap.put("jdTimestamp", json.getString("timestamp"));
            pubDataMap.put("channelType", JdEncrptInterceptor.channelType);
            pubDataMap.put("clientCode", JdEncrptInterceptor.clientCode);
            
			r = invocation.invoke();
		} catch (Exception e) {
			logger.error(e.getMessage(),e);
			throw e;
		}
		
		return r;

	}
	
	/**
	 * 从request请求中读取内容
	 * 京东协议中，为json数据格式
	 * @param request
	 * @return
	 * @throws IOException 
	 */
	public static String reqJson(HttpServletRequest request) throws IOException {
        StringBuilder sb = new StringBuilder();
        BufferedReader reader = null;
        try {
        	reader = request.getReader();
            char[] buff = new char[1024];
            int len;
            while ((len = reader.read(buff)) != -1) {
                sb.append(buff, 0, len);
            }
        } catch (IOException e) {
        	logger.error(e.getMessage(),e);
           throw e;
        } finally {
        	if( reader != null ){
        		try {
					reader.close();
				} catch (IOException e) {
					logger.error("关闭连接异常:"+e.getMessage());
					logger.error(e.getMessage(),e);
				}
        	}
        }
        return sb.toString();
    }
}



