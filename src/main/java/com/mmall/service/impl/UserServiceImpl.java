package com.mmall.service.impl;

import com.mmall.common.Const;
import com.mmall.common.ServerResponse;
import com.mmall.dao.UserMapper;
import com.mmall.pojo.User;
import com.mmall.service.IUserService;
import com.mmall.utils.MD5Util;
import com.mmall.utils.TokenCache;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service("iUserService")
public class UserServiceImpl implements IUserService {
    @Autowired
    private UserMapper userMapper;

    @Override
    public ServerResponse<User> login(String username, String password) {
        int result = userMapper.checkUsername(username);
        if (result == 0) {
            return ServerResponse.createByError("用户名不存在");
        }
        String md5Password = MD5Util.MD5EncodeUtf8(password);
        User user = userMapper.selectLogin(username, md5Password);
        if (user == null) {
            return ServerResponse.createByError("密码错误");
        }
        user.setPassword(StringUtils.EMPTY);
        return ServerResponse.createBySuccess("登录成功", user);
    }

    @Override
    public ServerResponse<String> register(User user) {
        ServerResponse<String> response = checkValid(user.getUsername(), Const.USERNAME);
        if (!response.isSuccess()) {
            return response;
        }
        response = checkValid(user.getEmail(), Const.EMAIL);
        // 校验成功，说明邮箱不存在，取反，邮箱存在，返回
        if (!response.isSuccess()) {
            return response;
        }
        user.setRole(Const.Role.ROLE_CUSTOMER);
        user.setPassword(MD5Util.MD5EncodeUtf8(user.getPassword()));
        int result = userMapper.insert(user);
        if (result == 0) {
            return ServerResponse.createByError("注册失败");
        }
        return ServerResponse.createBySuccessMessage("注册成功");
    }

    @Override
    public ServerResponse<String> checkValid(String str, String type) {
        if (StringUtils.isNotBlank(type)) {
            if (Const.USERNAME.equals(type)) {
                int result = userMapper.checkUsername(str);
                if (result > 0) {
                    return ServerResponse.createByError("用户名已存在");
                }
            }
            if (Const.EMAIL.equals(type)) {
                int result = userMapper.checkEmail(str);
                if (result > 0) {
                    return ServerResponse.createByError("邮箱已经存在");
                }
            }
        } else {
            return ServerResponse.createByError("参数错误");
        }
        return ServerResponse.createBySuccessMessage("校验成功，所校验项不存在");
    }

    @Override
    public ServerResponse<String> selectQustion(String username) {
        ServerResponse<String> response = checkValid(username, Const.USERNAME);
        // 校验成功，用户名不存在
        if (response.isSuccess()) {
            return ServerResponse.createByError("用户名不存在");
        }
        String quesiton = userMapper.selectQuesitonByUsername(username);
        if (StringUtils.isNotBlank(quesiton)) {
            return ServerResponse.createBySuccess(quesiton);
        }
        return ServerResponse.createBySuccessMessage("找回密码的问题是空的");
    }

    @Override
    public ServerResponse<String> checkAnswer(String username, String question, String answer) {
        int result = userMapper.checkAnswer(username, question, answer);
        if (result > 0) {
            String forgetToken = UUID.randomUUID().toString();
            // 将forgetToken放到本地cache中，并设置有效期
            TokenCache.setKey(TokenCache.TOKEN_PREFIX + username, forgetToken);
            return ServerResponse.createBySuccess(forgetToken);
        }
        return ServerResponse.createByError("问题的答案错误");
    }

    @Override
    public ServerResponse<String> forgetResetPassword(String username, String passwordNew, String forgetToken) {
        if (StringUtils.isBlank(forgetToken)) {
            return ServerResponse.createByError("参数错误，token需要传递");
        }
        // 防止TokenCache.Token_PREFIX + null
        ServerResponse<String> response = checkValid(username, Const.USERNAME);
        if (response.isSuccess()) {
            return ServerResponse.createByError("用户不存在");
        }
        String token = TokenCache.getKey(TokenCache.TOKEN_PREFIX + username);
        if (StringUtils.isBlank(token)) {
            return ServerResponse.createByError("token无效或者过期");
        }
        if (StringUtils.equals(forgetToken, token)) {
            String md5Password = MD5Util.MD5EncodeUtf8(passwordNew);
            int result = userMapper.updatePasswordByUsername(username, md5Password);
            if (result > 0) {
                return ServerResponse.createBySuccessMessage("重置密码成功");
            }
        } else {
            return ServerResponse.createByError("token错误，请重新获取重置密码token");
        }
        return ServerResponse.createByError("修改密码失败");
    }

    @Override
    public ServerResponse<String> resetPassword(String passwordOld, String passwordNew, User user){
        int result = userMapper.checkPassword(MD5Util.MD5EncodeUtf8(passwordOld), user.getId());
        if (result == 0) {
            return ServerResponse.createByError("旧密码错误");
        }

        user.setPassword(MD5Util.MD5EncodeUtf8(passwordNew));
        int updateResult = userMapper.updateByPrimaryKeySelective(user);
        if (updateResult > 0) {
            return ServerResponse.createBySuccessMessage("更新密码成功");
        }
        return ServerResponse.createByError("更新密码失败");
    }

    @Override
    public ServerResponse<User> updateInformation(User user){
        int result = userMapper.checkPasswordByUserId(user.getEmail(), user.getId());
        if (result > 0) {
            return ServerResponse.createByError("email已经存在，请更换email后在进行更新");
        }
        User updateUser = new User();
        updateUser.setId(user.getId());
        updateUser.setEmail(user.getEmail());
        updateUser.setPhone(user.getPhone());
        updateUser.setQuestion(user.getQuestion());
        updateUser.setAnswer(user.getAnswer());
        int updateResult = userMapper.updateByPrimaryKeySelective(updateUser);
        if (updateResult > 0) {
            return ServerResponse.createBySuccess("更新用户成功", updateUser);
        }
        return ServerResponse.createByError("更新个人信息失败");
    }

    @Override
    public ServerResponse<User> getInformation(Integer userId){
        User user = userMapper.selectByPrimaryKey(userId);
        if (user == null) {
            return ServerResponse.createByError("用户不存在");
        }
        user.setPassword(StringUtils.EMPTY);
        return ServerResponse.createBySuccess(user);
    }
}
