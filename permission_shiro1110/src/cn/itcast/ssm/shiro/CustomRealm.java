package cn.itcast.ssm.shiro;

import java.util.ArrayList;
import java.util.List;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;

import cn.itcast.ssm.po.ActiveUser;
import cn.itcast.ssm.po.SysPermission;
import cn.itcast.ssm.po.SysUser;
import cn.itcast.ssm.service.SysService;

/**
 * 
 * <p>
 * Title: CustomRealm
 * </p>
 * <p>
 * Description:自定义realm
 * </p>
 * <p>
 * Company: www.itcast.com
 * </p>
 * 
 * @author 传智.燕青
 * @date 2015-3-23下午4:54:47
 * @version 1.0
 */
public class CustomRealm extends AuthorizingRealm {
	@Autowired
	private SysService sysService;

	// 设置realm的名称
	@Override
	public void setName(String name) {
		super.setName("customRealm");
	}

	// 用于认证
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(
			AuthenticationToken token) throws AuthenticationException {
		
		
		// token是用户输入的
		// 第一步从token中取出身份信息
		String userCode = (String) token.getPrincipal();

		// 第二步：根据用户输入的userCode从数据库查询
		SysUser sysUser = null;
		try {
			sysUser = sysService.findSysUserByUserCode(userCode);
		} catch (Exception e) {
			e.printStackTrace();
		}

		// 如果账号不存在返回null
		if (sysUser == null) {
			return null;
		}


		// 根据用户id取出菜单
		List<SysPermission> menus = null;
		try {
			menus = sysService.findMenuListByUserId(sysUser.getId());
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		// 用户密码
		String password = sysUser.getPassword();
		//盐
		String salt = sysUser.getSalt();
		
		// 构建用户身体份信息
		ActiveUser activeUser = new ActiveUser();
		activeUser.setUserid(sysUser.getId());
		activeUser.setUsername(sysUser.getUsername());
		activeUser.setUsercode(sysUser.getUsercode());
		activeUser.setMenus(menus);


		SimpleAuthenticationInfo simpleAuthenticationInfo = new SimpleAuthenticationInfo(
				activeUser, password, ByteSource.Util.bytes(salt),getName());//验证正确性是在这里

		return simpleAuthenticationInfo;
	}

	// 用于授权
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(
			PrincipalCollection principals) {
		//身份信息
		ActiveUser activeUser = (ActiveUser) principals.getPrimaryPrincipal();
		//用户id
		String userid = activeUser.getUserid();
		//获取用户权限
		List<SysPermission> permissionList = null;
		try {
			permissionList = sysService.findPermissionListByUserId(userid);
		} catch (Exception e) {
			e.printStackTrace();
		}
		List<String> permissions = new ArrayList<String>();
		if(permissionList != null) {
			for(SysPermission sysPermission : permissionList) {
				permissions.add(sysPermission.getPercode());
			}
		}
		
		//构建shiro授权信息
		SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
		simpleAuthorizationInfo.addStringPermissions(permissions); //验证正确性是在这里
		
		return simpleAuthorizationInfo;
				
	}

		
		
	

}
