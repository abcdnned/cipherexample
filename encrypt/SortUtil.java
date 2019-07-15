package cn.cccb.appsource.jd.util;

import com.alibaba.fastjson.JSONObject;

import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * @author red
 * @date 2018/7/3.
 */
public class SortUtil {

    public static JSONObject getNatureSortedJSONObject(JSONObject sendJO){
        Map<String, Object> treeMap = new TreeMap<String, Object>();
        Set<String> sendJOKeySet = sendJO.keySet();
        for (Iterator<String> iterator = sendJOKeySet.iterator(); iterator.hasNext();){
            String sendJOKey = iterator.next();
            treeMap.put(sendJOKey, sendJO.get(sendJOKey));
        }

        return new JSONObject(treeMap);
    }
}
