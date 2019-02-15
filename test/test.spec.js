var jwtUtil = require("../lib/jwt-token-util");
var chai = require('chai');
var expect = chai.expect;

describe('jwt util test', function() {

    it('should sanitize public key', function(done){
        var publicKey = "-----BEGIN PUBLIC KEY-----        MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCSjVCvVdFGVSAbi9P1Z7978FKa        sd4BhzbuNmP+rE2TTiSaGvprWzhyNN+4N2FXBlCnFpRdjbBezHfiu5wCbzdv1lgq        r+aOCLViCEE7kLTTgds3YC3NOsC0YHlD9nen6axVr4gmWH6+6sbq2Acs5QBJLYRg        5QtHuON+Ny0QEJ6GhwIDAQAB        -----END PUBLIC KEY-----";
        var sanPK = jwtUtil.sanitizePublicKey(publicKey);
        expect(sanPK).not.to.be.null;
        done();
    })

    it('should sanitize private key', function(done){
        var privateKey = "-----BEGIN RSA PRIVATE KEY-----        MIICXAIBAAKBgQCSjVCvVdFGVSAbi9P1Z7978FKasd4BhzbuNmP+rE2TTiSaGvpr        WzhyNN+4N2FXBlCnFpRdjbBezHfiu5wCbzdv1lgqr+aOCLViCEE7kLTTgds3YC3N        OsC0YHlD9nen6axVr4gmWH6+6sbq2Acs5QBJLYRg5QtHuON+Ny0QEJ6GhwIDAQAB        AoGAWteeHBFmF+LMdEbIrGYTHBBsI9f9dZULR74PXd4QeC8IIT532/Q/mQuNYfNy        My+G7wvgC924Zgr4hWMl4ZxvD8PykhaVw/pvIFyEomkU11d/cbcBUFWfPHrpe3vS        1OL1bIrZIvgq5PeN/GF8QkbMRJgHb8uRx+PMZ0LuCONCQIECQQDFMTsUMMpwH9LC        4Nk45qkglAWhBJlogRzzrQa9MY9Dfn1I7DhjhkgNXZ84PPwRzMHLrwslB2jh8lhM        9ImlcURNAkEAvkHraqiXB3l2MUfKAfStx+CYWRrWttN92g6LB2ABHrQMoKZUFif4        0MoQivcI+qJEGnkHY3InTJSE5fPjX4LwIwJBAJST95PK/31kPQWhLYr2IVDutx8P        vBdF0W65XG6JPQz57aRYeFRlBT0s4Z8aNEOlKBA0oA0SfDBiza2OQ3ho07ECQCEt        08U882GtT+xWLadbqTazNz5KzOkDRu5RHPPDTU6ybYVSnFVk0SJwKqRhYmJ7C89m        DeDM1oenWunTN3K/nesCQB1fnY9TF+jCBN0AUnpG6vnGWpbkOE8XRK+/5BcVDn/I        3UsrO+4kE6CO3ODSk5GNoeTXaAS6R+MOXHyWcqxVuOA=        -----END RSA PRIVATE KEY-----";
        var sanPvtK = jwtUtil.sanitizePublicKey(privateKey);
        expect(sanPvtK).not.to.be.null;
        done();
    })

    it('should sanitize nothing', function(done){
        var secret = "thisisasecretstring";
        var san = jwtUtil.sanitizePublicKey(secret);
        expect(san).not.to.be.null;
        expect(san).to.be.equal("thisisasecretstring");
        done();
    })

    it('should get default jwt config', function(done){
        var jwtConfig = jwtUtil.getJWTConfig();
        expect(jwtConfig).not.to.be.null;
        expect(jwtConfig.keyToVerify).to.be.equal('client_id')
        done()

    })

    it('should get env jwt config', function(done){
        process.env.JWT_CONFIG = "{\"issuer\": \"mycompany.com\", \"audience\": \"mycompany.net\", \"keyToVerify\": \"app_id\"}";
        var jwtConfig = jwtUtil.getJWTConfig();
        expect(jwtConfig).not.to.be.null;
        expect(jwtConfig.keyToVerify).to.be.equal('app_id')
        done()

    })


})
