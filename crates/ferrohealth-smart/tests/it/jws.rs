// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The JWS module against the official examples, RFC 9964 Appendix A.1
//! (ML-DSA), RFC 8037 Appendix A (Ed25519) and RFC 7515 Appendix A.3
//! (ES256), and every algorithm signed and verified in a round trip, with
//! the refusals RFC 7515 §4.1 and RFC 8725 §3.1 call for.

use std::error::Error as StdError;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ferrohealth_smart::jws::JwsError;
use ferrohealth_smart::jws::algorithm::Algorithm;
use ferrohealth_smart::jws::compact::Header;
use ferrohealth_smart::jws::compact::decode;
use ferrohealth_smart::jws::compact::encode;
use ferrohealth_smart::jws::jwk::Jwk;
use ferrohealth_smart::jws::jwk::JwkError;
use ferrohealth_smart::jws::jwk::select;
use ferrohealth_smart::jws::key::KeyError;
use ferrohealth_smart::jws::key::PrivateKey;
use ferrohealth_smart::jws::key::SigningKey;
use serde_json::json;

use crate::support::ec_key;
use crate::support::ed_key;
use crate::support::ml_dsa_key;
use crate::support::rsa_key;

/// The JWS of the ML-DSA-44 example of RFC 9964 Appendix A.1.
const ML_DSA_44_JWS: &str = "eyJhbGciOiJNTC1EU0EtNDQiLCJraWQiOiJUNHhsNzBTN01UNlplcTZyOVY5ZlBKR1ZuNzZ3Zm5YSjIxLWd5bzBHdTZvIn0.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4.knI1Q_9CIzLH5Xy94Kkc7WVKqZcAgtJ3mNf0GUj1uLA6YXAWFJfXkh-zQxUtEl3UIC7zPCiUwKTDR6ZsuUmFj8Ctb_6aH64hElN7weS_1m5okCy8GqHNL2lsfclCH3Y2f4QNP-DLVS1XsuboDA7Dw3ir2IdYKIfWJyIU7ROHgd24nuun1zJbxcLJC2EKt2M8R0wZudcIE9nm5oPzYXq0z-hPsKoXp9leVYkqgMmO9Lo8SP_1YYIEth3B8v-GuP249KDTFRKPjISmK4aPCknjtjihHsQVv2XePXxKExatHl4qhsiiW-y-EJXa1Kfw4WYpLA7B4_5Ids--cIJmIx7f6xxAWKh5qoBWq1QIOaaFuzsAraRW3NOEuzThew1En85gI3GcRTZGp-VDGyxHm0Al04cyWo2bxAVOF0fbDc265iP2mCNw6Qg10jIJeAhGB4OAMYcBUWJAG0l1MN1U_koEmGh5dXKnQTRl461ea_Cq3DLkcA2Dj2woWUFyDTmQ8oO_yheASfJacyRm7_suj88z5XFNo8F53P8OxTG9xUPlrwvH-TAq7AH3NU4SNXApyVKTU3zhx1tJ34nlTILcTujXVJVo_f0DZfUxr6JSCYqvy4z1Kl0wDQzd55aopyFtQxvOPhcCHbAN34g2Ug750Jm835fl7NOxcqoMbuTcgH68kr37M-Pdh2K9WazXUJgCupgdIWW8WjfOjmTiF59CrVtfVtK2qDzF40OENCfqtNPQlZe5cN5p0P8arj4USB8HCPh7NdqQBAeWrw0wsYhdiM39lrSkA8mLRYMhZnqKGCTPCrHXDdEjRKYRNaqIUT44laYl5c27K0v-ozjKPu6tzEhkYSC4XZ3LehEFtmAzOE0mHbhKMgXqjoPJjOrGIPibX3jwK8_Q5RmMOXtXo8R3vXfBaUdQoLeeyywNYE0nIcsl4z5a8_utwEFiVf0VK2pdviyiOPVSi3zOMAmqz6gFhVy8aMMQOWZAEAuTyDw7ZWG6diwptmrgSXZotW63I19S2ZH7keCXRIq_pFLuYhOuG6dD4MkouILRdC9bXZMLrNDq7COpUOO86aQVlYd0pR935WpUw-V6obSRnHlRFZSmUSIB7h1Q0ImciRzojN93Xhw7qpzGzdzDEO3OOTayXaSG_0YHQyy-eH4hBbmgt_LBx120g1eY4XHeHFRfTfetHkL5ZZusX1jQ_nk9ez4XBG_6hRtTNSuVBsYlH8-KUuR5-qTP8dkvRf8Wk2hHoUr2sz5YO_xDFCMMTrt8ahiMyfjo5ih5Fwo3riFbFUGKibniTLXspFd4spcNK_WchlZLRgkPK4jh6Z_X8JJkHxvQhpyouHQFyGxgBrl24x-_EB1zbWMhJthmm8DiKt-nzKaJz8Cju1-HwCpg76CRqRsEz2hyKEpbb4M5KQSj3AsENCroVmQ5QIv3K2XNRkve4vjBmP6sV2b6GSY_UeRvPElA7SUgBGTKbn-c0aYhBuB8plPhRTBa55_cFqAmNmavF1-fdMktJuIaH2f-K0zZCzbHw54998T7kIWgyMsyGCAvynEB_khOqwT7tCjg5HQ8SIjdnRYW0kjZfjt5LJbGA-PnRo8gPVQVGeYDP2vsSXhNJY94AitKCY1srcSsuYDrhNBKrnoJ1uEsMPVHsgFw_ZHMyAEaVQughSNW4fm8q6_1Nv4zLutDITzmAL6a6i6-WS6QRIs_4VUtwr5cXXIFDDeHVWeGcNivQ6W9urEUP4crguiq7z_DTiYaGfUksub-T7mw0zU8ZoOSd5pUTpJLv-IYIUAl6CscHvunnRLEKqpW1Sa1dcFZs5VP4AfR3mg7wX4Vlq1AHnpFxE2L1LZiKoTc9jDEOvTDkxr86gMkwMm6RdyPF_q48AVJ1br8Qp88-4B84X52zZ5cw-IJYe-HiVJ29LpeYm340_rWivpy-UB5i9TKlMrxf94y1okzZTPbP3_v1_XX0nE7RTLz98EA96euJ7l3EpbEqks7mh6i1FJNnvvlM_u29sYobJ6PUT-i1VlQnF_JBARKEz74pBXm1l5Y5Lo15rsIlaQHinUBCO8fHCHI59LAfKusN4JmodDqLYwkWijEL_sfrC6LtrbXqpM1pw09zSrs_tS1RQ-LnWHuPrU5KLCzv53JKrh8lU_cdBowe_F-Ib_Ui4bQ2FME-0mnyG0XijHUsrGMZ9dfowvIkr83JpqwlFOZAwMmSGPNPEJRw9kDshjotndUB5S1UCfv_U4IoVn7WgvxeCS-BBxqyWfh7YTdf73EnmGwVYxVjlXaHCeeTZmUacnT4MQUAcbFjTq6BBlboAQGWP2FZWpd6HNnruv744VeWmfgLk9z5567wFhwuXMkmE2xvDo4wP80xutjUfsePx5YkLxhY1XsWqTZr19tInxJWWq8RLZsWPmtq5wZ5ucBMasCLpOABenYZdSAcQNhC73wLS0Z2s1HQhBoIl7lr1p372LZs_Seu1u_8Fo7DoJqRpKaNoc2_JUMmn7TUZS8zLyzxgeq8R8iNbRP20DwDBNXocsTDBKaQrtB-QiEPySQtJa4G61XeNZyh5aGzfoWZ9OmjZG9pbbehcqwIrt-ESjPyeT6sfSrvOfTZr7fBXwpUs2rS4BrlNse5g_h8CQiik8aaOTOEPkXiyg4s5DewRlgDZHS-3g-YXPUIBNO62_HxknkMpkJvKW-tkvDbgtxvy4nG80ul6W_KeRsoEKDTRYNKZWxXjZITNa0h6agnwNCJKEbFg3Qhre394c0i60mfP9YIgKTXrCX3Yt2eX-6mPzYmLbSbV5jH69v6WZqYV2WAj-9DU0diR4hOfYQaJnBZhTtKb-SQsYiFuN1BDJ3v9eM9K8hq91NBdCHVa-Thk9Dov-JkcTZnZGRRyW5yXHUV4NOEltBXh8GkjjDvs5Yo3u-2rPCXjK1aGPSI1W8BaUJLQY5sbfAVCAuUHBv-Vlh5Qamt-lgeKguhqTSuy-tjabOb5kiBOG7xGQt3z-XYXtnWFDCii-5h11XfZsQ-xQxy8gSfdMz4hDK9Nw_VQt6fzWiQY0Th_dHzVki0MUfVfsDUjgblhD6j0wgbs3zdj-GM3rtt8oit0wXx11bIOaOKgf07tP0wimVXMRqRWe7LCUAKTE5PkRKU1x_h4iusrzi5uwKDhc4SmRwm6KssNrmCAkiNDZCREVKd3yMnrjA4PAGDzdKWVplcHJ6jKmrsbrEztHd9QAAAAAAAAAAAAAAABIfMEQ";

/// The `kid` of the ML-DSA-44 example of RFC 9964 Appendix A.1, the
/// key's thumbprint (§6).
const ML_DSA_44_KID: &str = "T4xl70S7MT6Zeq6r9V9fPJGVn76wfnXJ21-gyo0Gu6o";

/// The JWS of the ML-DSA-65 example of RFC 9964 Appendix A.1.
const ML_DSA_65_JWS: &str = "eyJhbGciOiJNTC1EU0EtNjUiLCJraWQiOiJTdWl1MjlxYmZ1YUJhUjRBdHMtYzZYUUJlUEJfT3BBeEF3Y1RSXzBLWFZNIn0.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4.zmO9_0bLgJAegoVNymfRo4nGPK5lVtSFGnDbzfzYAD5mUEXpaBUg4itvZ8rAUZi4HLb59QqDQSBSpMXC0axajXOMV_YttfmwGgC6FMyaMRZkx-A92bGiNLutqX9jcwRLJqXjMkUGhz2YpHe_mV9QpxokRCH9K6jkyFZp4hZIwFXhRt1z0OGIa5rOoHKsxOCAUZhTXKiASb3vk9lUASW0-Y58WKT4rVmst7_dvk7FVbe9A9I21IH-Tqlg1zSMoI8ozh1aBSG92uPursBd5KRcOlJwhNUYJDgHScIHXM6Hzk6u98W5orKPHu1rDIK7rHJI4Zrui4wBjmQLsPE01LcZHRx4zexDCTMCGSojbL1FiT9CU3oUep4oWOytTEAf2eCi3qDD0iSrp5IslCueoNjtGOFSnUKlsnCeiZF-tNqTy1KpJ3ErTaNPcCzCvsEalhJwFa7NOWyQOEJUzcLaPY_VEFwcCX1Gk4bEI-1rLDiyZqkXgny-U2oRnll0d3u-e2S_Rg-_eL1H_XEbPs_km-822G7JY9li4muZ5KVvfQf_5hza1V4GweqvmeWuZL1gBU2HPS7x1tWL798ALOk1rMnxsvBOPiSLxAEdPoIuw0_qMlKjTavJcDFaihgCgGMUk5SjU65IWQS9t4rgxv9Idu0OCsozo9iCBqrVcnaOwUpkMhV6KeiXA7kQNcegVaMio40cjSyMiEkhGIOEOf8L6eohOh_bPPRYs-8NrZ-VOBJCa0ubJcDU1cTuGNCa7nWWxAqfVjcMyNDx9XHBYBnSOcFNfMP7S9nvqw3KC50U_t2PH5SfwS9w4DLvcgrlEP_gwSgOXuf-i0tRGLQly3IMB7O8QOnkofyFaCUDZeurFkGTpoBfT6lzbJznQAMIDPNcWUsRlNTXsH7atC1nxl4xDJLmmPLCxiErfxbCW5gMWox0kLDwfsFj57hsXG75cZ4jiBbq9b0VjD7Vkf8xlc06ExdzBhGXz8oJiaT5WHDsuzGtrFmh6diN1cO4Cxjr6KdNE8IlyxsfXxQ4AI-0ke3gMyi0DOGeHgHuNc-JHD7oZ6njUMSTBkR1aUMNT7n_2nfFTDCdqW1HaMsMwIHfLOk6dayKXE1oMqY5Op8S5k_SAaknR0vNxmhlTA5h3bZJ28NZxM6R7D00_eBEYrH20rmRP7G7kXKzLvmWeaKAh4oQHiqjVhgauiePDRiMmjx0OhdQnMCtO8PWbx06SiviRn_5hswdVV08B48MVHqbM2AxCLLJYinC2Ep0302Uo0DI-rTNZ1Znn58kM7VCskcxDLsH9AYvPz-HQr3H7Xg0ElwjYn-jJXgZ_cdnLFt4_TuKQdpw_qhvyrNjOx0Mdc-1PrwoWqpA9sSv_pS5lwI2qNVHI2Vj2mZHByod1QUeOQExf3SBjP_FHEAUzUu1OK8M-1SQZGzJT2su3a6ZnMnp0U5qdXyMONFoI2jJ2hDjt7QEQsLx-rvaLxZMJtc2z0MHdwJGAC_kug7XjH3SWQZzBu7zzreIaSwr2A2oobeZiAydwb8LX2QsY9Jr_NphGAMAqzrpkuaMyBd_pFTKMp9s0GYxwyG1ZD9uRuPI9imA4CS7bt-O8YvbWg6eQ-qa9OqDlxNt3Xc32TniQFVxVxN6PDY33XXU-Rpvd1w47NZ48nkyJzjD8Xlbvk9p2ynxWHr-Sto5HXZdru4j8ETUW7ri3mEG1m_dxAbAe2kVbsBp2I1vQppugbmRexuMRLdYFIKqNm0qpQoWTr_k2t5KHnWolrSbFH7Usm8Pwyi4sNhh4_yRHADO2q2o19zCCx2plDSMeYI74CQPRGLlK_GLM4E5Bzfny3E2eaE5_gQBTSGNHpQtJB0ipPwDjqsjDCXqXupCkRta1vxng4coi2-vWYvKu6mq9HhdovHAaWrZRyvuPPI4ZDN_NkmfQR8HogR6NLVhLlRp1cwMArSSDA3f8QlnjdbaeutxRXvFnCCjBk79ws8VGdWAuRmIWgoEFeVAVxkJjJ07zOW8I3kNfB6pnxsZmJwWAGqWc1UlPmkNBstmSXinAzbdl-W-kn1XRDuhzTafHnkCbKS5XgJKsWD2FrhcnCaxxRxuxIGxijofjD4ihmJoYDFh1FYs9IcC-szEfMSekanWOIZCHd1fVzTSbLr5bNaOXR2sO1muFX7w22m8pBVD3fyOHK2JnK4FBCnEBrruMIDaqqu8Z4xesAHKfxY67w-25eUuvVCGL3xpXSyp90684ICkG4STztP1shLVsxKDA-37sKKplqemERlMPY4vDM1Np8JlVawbSGIuom20g6p2KV_zpIPwx9vd1nAiaeZbryf3N5gtL-dOq-c6uZhTCx9OLBtLGE3BcAmn5JFjMGQFxyTL07BluNu24Kf-lttGj9jzbwPZYrok-SnMilXGFEqB3D3cKCOlWjsgg_3cUW1uMp4KlWQvkimV9Pd7cY70w607jcYBJ3MlFZ8EeWeYPZ9qu6xwidA8XlLHxXxfLIJOgfpU8MTppfxdnMhqNSvH_Hx57oDphbUks5K1Z8-O4dSnNqQ-ZWbhaAydYQFDKuUF6HYTAvaWhJmACxhTkTp2t6-P3bev-FcdFIdszJC9LxWtJ96LY_GV4Qvp0hiIdyP1BukWNHtsXK2Rxres3_4Cndg2BOGxVcKZ9YpQDCUy76GRbTCenqjD-SG5sVUEVha5yxbKArPr2-Xpgk8cuZBRSAdmPNRdxCgUtldfCLeL7xhJvryMouxfQ75PMBaImHcsMd95075ePt_VkClUaUj55Y9E81FbOEchPfud2w3TtSvRPvB8-RgY8sLJUAclxcUGE4PnKSZJ7TIBUtHD6uyZ0-nC5KGxbXZsBEzUeHns4ix0Wmo6-6vAM4PGK3qRA1VAhtKXyvNcAfVccVi8KJMK9Mz2eIOXPATvyRy34Ltrcg8tcgK0ftYqEWYpAZ2fVpZBXcYfTIinuLN0-qLra388EZuu59jvmRD7mUv1msMWVMGVeBoNP3lJaJGGWK8iYyu4q7Grq-6WXr5qCz_7kwAtVJdb-zW8U3jLJ3tRSYlyjlpzeVAGjDQ6Yni5y9x4BF-5QUqcoGMLLglyx2WOCELT8IW7nsV21QnqqAbtCzZ76UtEdmUuEOTyqiKQZ0lrjMRm3YrCvJKxtR5thhTRka708NzBvwSRs-JxGG__EWjHhT-aB4VL3IL_oz3mt3iQoszfA-SzHcKU1laZMBuUCyxks6KiJgQGZRPXyaxxDtqZdaRP8Ic5CmuPeyu3kafi0L6LFijsUxnSGxTpgu7hfvcmowQijfE9_ylvg8k_EbI2miG11giODVCYb7k9Yjyriwc9dSUUZ7XoiS24hWYUX6BGGQNN3wVHPkDkOVSDBYTjto99ulquryx4K_UMCu9sQVNxBfMh8tLN7O9-MXlnJbHfKfqFHiPGdIYOBpwuqJdAJiyiuSG3gJxMG_wuwNkBWoO--iOm6PIarCyvL8_P-tuUfT4zIgjJJ3o6YJhbo-q2K82ZFmHuILyzfDSGtHDZpZIR7XnRQWet90cJEHL5k653kvyEHJg0iUiE0iwNA5d_4gBq3vmw1J74hwAHx0Z_iYEcPS6hDGow8M8D7UJTZDkUV_86zj2YqGm_QC_aAeD__NP6sa61bI9-gTOzvYc0JiExKTDjOK9fIvHaV-HN4xr2vWner8o6jPyETvGM8D7aEezlUVOEFwALmhJPSMAq_Fk9JlcIUuC-ITJZNtNz9Awfiru3wkPja1bXN76WAuRHjia0x5ptgMCy2py_vSHZybfIS85ZjsOQ-i_e_niBzhyzXwzBaLEyEitbF4ZQx5c88lXKDMpe9tirAI6XAcqLf4UZkD8Wm2YV7hhVfxLQ1AWLekWE9DZljCtE-SbS1EWNGR8faXKCvaZznRyoqdWz8IN3w7KvaA_ZrEKkIXkkreztG6pI06DlDHCl_sU6rCOoyQf6y1AY77Ob4SdkSRoBHGgR6Uv-LrxHpyJ6trzccu0kqxubHrkW2yHcqe6enVf43zYwWKUeJJZ10bt3a92ziSne-3aj6v3guiKoJoLnV_9h8rUF6zorTWE-Tq58tYfb5SmGf4iCJ5cy9LTY0COIfwJtPkUmyBCZwUhWJnV24P5pOZPe_CckQ28xv5J7Zf4Bvqrq_rhubFEhTJ5JvdMfz8Whc56WSHX7GRKEMqXVp3pHohBvOyT9BmotzIlibVklJy4gzkzUcjJJOld-BOaM_cnMiHpoyKXSJAXTNwXngzEpbvDP2Y0fnrgqDpO3RR3gINaZLRmeG0WI4wWBMMfw8PHjpyV17C_1hmfRI-darbZcX7PD3N4Rw4lBACyk_wnOHBcAS-5cLZEzNmFmhc4iO4msz_seQ1N0drbB0NoUVWBmcY3pGC9TiY6f6Pn-FBUnQkuBhIyPtgAAAAAAAAAABgwVHCUv";

/// The `kid` of the ML-DSA-65 example of RFC 9964 Appendix A.1, the
/// key's thumbprint (§6).
const ML_DSA_65_KID: &str = "Suiu29qbfuaBaR4Ats-c6XQBePB_OpAxAwcTR_0KXVM";

/// The JWS of the ML-DSA-87 example of RFC 9964 Appendix A.1.
const ML_DSA_87_JWS: &str = "eyJhbGciOiJNTC1EU0EtODciLCJraWQiOiJ0Um4xSk5Ja2dNc0FCVlFCbFhlREh4QUljY2xoLTJJWDBVZERFelB0NVhVIn0.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4.hmMrKkUgZwGPQV_WUoXUVq_Z9WOenDZbfMmHpKritl0btWi29TC8eIyQyT1FAuW2kg3h6ALsvCrjX5tn3QKFQZYC0sBdRt0VNiDm0BjyJ4jWcomSCgb0-cGXaLlODAz-njGridYfO1DpGMwHHshuKuvECv4qnX3XgZPE-6C8La43TZrYO8brzBXGiuyGMLq-TSmXavOeiadtpp6iTUqJDBgQSYvPB6PvipeCPlQH2ZQi8qkraxspi0lgy8Jh2aRYj44DX2ZKq-Ml-hfBJB4iHRpWmwPpEH7Ed4LkBIlaqZoPccrPgpGQpyz4_FcahrJc8CGGtTO5I34o5BcuZej7WOQvJ6mRmvYqIrYwoLs-3_YFZkVdX4KU38oprMvAHjObOhy_vZZArMnCgfYlCKrANbhOZG8O0BXgqow5Bqv_oRIztGQZMrivp_1CS0hELarwkwjdqyH5R747ndV26IQkeyn6y9daXRZIWxaC9KmAaDSm5-YsRVpiAAr0QmfaV51z065_r5qZmOMFIBERVi9Bbm_Z7ipJkoIL2SqVsePATfHeWB8huFpVFxdeEkJUPDuBtthax0HhxpRuECpFNJf2xA70Hp5C5VZIsi5EO21HuRpixiNKmXP5whhsn_uv_B7R4f4DX6X6A53lFrUfpFIrTfOQvBAvmEUUTSGcPeT-F7f_1lz34uFyN3ZT4FCeCh4n4yyZY1fSPVMNtOfK8GrLrRoWdi8gMk30oTKgb9zFkFU7uZhVEVRV86A_060bgFSHWDz5dlXLfyCoJsbsHlO9WBibTCkrMv6lnjh4czprro2prRtJAJB2jVwS1dv2mo4wP1lFYqY63yM9I9deU4fxy6mkwig7XwcVJskg8jX_0agATqmrKfYWMI4yGQ9fciYacgN8X2uSHqiPU1cgQ8VUGsSAsw4POdZpmcUt_DacVLT8-qwnq6NWpm8bqm_uUQu3JjqcHKLz7zWKopeLG_ZY7a45IqUQpwbMg9ICE1ZNTe5nsMHAJnevgLfWk14wnvVQyRVvlSvatdUTg0EjBc6P35a4lY12vIOq2ENpA-m52TfXeXxXK0vtZfT9SY33thi4EfZABWL_jQyiio6b6Akrh6_PgQ-bh2H2Fpu8Z3GImrbHodcbnqFpmKYlMLwxDHnKPxY7PpyyV8HsWfEjqVlAX56stAIIG4_owwzMZMcFwgucAP176TwjaXJqm9v2-DXisD2cNjyGlJ_rec670rv61thjiJF2uZrB9Z2zoQVYnc3Y9sJMMPPmunUcXpNVZWSsPlFDoPa1ABoFnRbP8rO-qbNGP5N7xY2DuPRYOp3CdyxeyDPmGBC2556FNeLRj-PhPAkd61fgXsQZyS9N2jHmFUIKbL8o-e3bQnqW7ebEn7zAjS_LQ2DtgIdIneUu84hh8AduoW9ky_aOpqvBUmdnHUwZHQiSSdeCPnEOssVBbuDd3gbcQf_VWvplwcjTTrJPsqqZpirjfVGPFUCVAz6kD0vhFcvTdQt6DGqys61xg_VOfj6wxpKsXuXDuqwaeb4KpGniHx-23nECgKG86N_1BBX8RRAvYnksxIIxIxgyrng-y44CV9FL_wGfP0Plx6JjSUFOL1gDZTc5NrAPoOztEo1FbJ2Lq8gqBR9Ku9Yza3aYANAJQvAraTXzA0t1j6qcmh-WtXeI1GE-8neOJtlRVbzT5RvPiRJZAVmu9Pg97wbLLQNPJoqIYp-c9mieGsDxAi75C2M1ArRnCa4kJJXrupgzQzzFefWyaRkIvC2MP9MwB_Z_NY3mp3opcNlT1TdKLr1sncLUkk3qJ0Pwyr-5dsKrC6aenapBHO7G0OnA0qTi8-Oy91VqJYYcVjcOUQaxNeMtnk-pLJL7j3MzqNiDkc-OfR19fcWvDmmd9Z8wtj20khL4mTDn7qTUo-PsVR7GnpqkImmEmE8sa4ZlPHa4_IcZGFbdcwp9xuOndINlzWGrIKywFPQ1x26zXDEa7fOx5f01aX8dIU_KWNAGdaZxPIlqLW5qbC6dipSqf9NwblZLJs5DCiLV8nHS-QM26xQJVUNH22n_3Z_8z1SA8AX8d7j0-g1Pf7NZC8e8Ipnm4B3YGpA7nn471aTbJb4OUamfgys17MV_hPDK_f7FF7NXp06-dtVYDmcs-87ZkrDuluOkUaRivKULwjEtSbiiKZAKirGfAOuwyCbbzygEpqYvEztABSmDYd_F_autklob_0deKuvvRYFpVCaxeaYQ7WIkpfBbMxeh9Qci7kPfgyB5H9ajWEJV3fgRk10Q1RaWyTUddQ_jWaluiDa3GD_t39sUrG7QhXc2Oz1NPPNoY6-A4jFbFCtXSF1muztqy0xaworcNiHY18yeL4Cw2iYLJ1Q3O4NnFo3E-wIXmYF4CLxZifr2Jkd6Ix1w-wlsN6vyCcDs8JeAgeJn0_Oahk1mgvRhVz8FFeidSdFqJBxGKbfZ32F_auJwrsLyjN_ShxTSFofyKQy2XCfoVMko4eu5o6md66xBmjZvTvItXL7f-eD0JxISBsBkZG3mFrApZKbdpI1lEa681ZbCxRTYpxUR7McTbs0Q5S9PCN5ElUz_axfeupIIbCTE4S0-ZQuIdQcQ2pn1j-4t2c04jtLE6WFI-1ASBCedlZmrZUiRegbezE01hMiFnfN32BhBu7ZcnlBCdWwj9hUfpEduJIgaA3acXhysGs40nqRzR9imvX9CBQYJZjrCHr-wORF6svmvF5FADRgwbM7Cc9puJgLBiQwXrhD43B6kjX_OXi5O2UNZFkAPr0WONBJsip8CgR6pt1u_mIKlIrYM9kM-idJGGT0DZ9UU4LMx0-9_2KCCkjDqgYN1rS9DA__GP9tS3dJ-XLSlk2URQuoHm4Xubv4vwgjUS7JzAxcQWHB0HtHFoZ3-tYVw_GRbRwyODm3E-N5O3L_R-pva9fvlPjkCNMrf2IlxAxBKML1gCxsSqhFr5yoPeW40LTxMF_dYPNLjC3l7mRRl_wfY_FhvayI7hrgCYfMgWeb-cXyx5eXumt9lMFOD3dQtEG1IUbdE7pVXG-barWK0Zl43DtQMNQzoCK_BLxfCsambyRRcI6E4QTfqe5lWtVf8Wi4KproenWyCjjzEjJQdWw4g-ae_bjGjfZCp38RgsXtWgI_tuzKyRF5WwjyN9VEoRXd8W2DctmBejHF2XDYzbMFkJ-384SokPX6intnlqBGMs0ssxriJhsFOA-vgDra6REx3DUMb8_u_Umc-zp4E6isX4D-eRYgElmj0ez945nqxp3YliO8mRLMW6E4OupLthfw4vmK3YqTAuXcnGxYrf7JqAkMfz5uAPi0SqPWDQZq7ycu9BmkMXAIhMb19XBDjL7hZGDwDRrn9yBBcYlPaFPNXjMJWJH_xxUKNsTFGg5-J_WdxXi8Zn6tDMxbxqqjIpw_FUaM00jJ2MhpbkzhEx7X85pBR47ScRgr6WJpf4ZLSFuV7NT1WI3PIBa_bYeCiq29fp3ShM-1bRFdJG_lGZd97TuAMF_QU6-KDXBv5i8kUZ1NXdJUz-YaA0RRVNFgMGM5n0pKB5IFncAPK-taTzHLIZJ9uuBdP2y2Hxwbw8YQlmy2-MT5XE5Ae_9kxuvIIlSzjpfLN9012HSnX4tZ8x3aWwof3E7s3jjzw7qbBtoUkYYpIGVOKf2EpmhEqevSlXYWpBYN3X2ZYjsrA9CL9PTvrPdyWLwKBmfh7cDJbjNXJSQLeKL7oHzicrllABzR9Ckkz7b24XGV1Klcat_Og4oB9qxiO2zJZWz2GDTAL0hosUlHLWnrQYvqFzzdIOzGlifwIyGgoRNb44IRMzzsErxuoqkdjZewVc4PzruHRlV3cWK6M7ZUiWLtxtMzas2sfAERy8BdS7ISLzj5PERoWyYXSW-898WD3ze5MJcpSsAYNEmPCBtdxF9l-Qz1LxuDa8hOCQ2Wzef1a2WFF5pCBaZRcAK_kef65xRst6WFpjWZGCLZUqHBhFDLEOd7Ikbw7d9V8dc4nAO65NQcxfT9JDUZadS2jmQJip8GLD4P9lGS1Ry-8rHCnMN7zXDp43TfyYhSgv9uj4xKi2wmAMMYBl0n2RNemx8nt-K_dknGgYYGOybDkg2uAUoXdxP33KfiRjbRpYqZVAiq0S45QLAIxxGiDJoZRnyIscdM6lryQtXj0PO67vRf6ifxC3wLv97HHUKergpXcAg-4_rNj_Zx_xiHMfCAe2q3DG1a_DcSmu5u1OPkBHmzHB9Vs8HV0E2-z44sl3Exqb5L8pMYpDnZ7QW-Qb1-S-zoESUy__AKhkRWPC7GmvmJJJHur6SRGSK0X2KyszkEYoe-8NhwpvLrYnNuVk7QknBS91KH2q8C0B8FKqcY40S5ILkImP9iOGIXYl5ZVRleoDBpH9BootWH2az5l7c_e-vfBGs7XpudoAq5wzhe_-AMBvKPCm0BoCX5B_NGUasXvEWobqUb61mpKCuVJdzVtexk-m8Jfvmdc8ooPJEYD_oosY5_S1LuHoc7GHLnoYdDVb2FhIPhOJCLQCef-Y3dtNThqOEo534Zg7R72nSeSQhdQ1hcBUsc50U2oF9OlOnV9z5hsfNwIxdUO9bdoXRYFmosmtpmDfGxAem0s5iPJ0EJ_8szlaX2pi6k6VP-ci-n7J8pEBwL2R3c-ei2iqB7JdLi7Gg6iXVMpQIFTxswh0HbgGtyZXgR_-AM91XRszm_kAlqAHTAJ7B-0Z5bJgMGEY2StBdhGzel_gNPVaxemC3DT0904GbCU2Z3avUHcedebI02_MdILdQxyXbw145KjqC15CqeaG--6x6WzpAuSjrFQRuz6Z5UyibW6Ay9R3P25c-gwmaRM8rPW5YkQtQdfzrtvGZ6wyhIcBXvbpU02OoChfRDF4xI2LvnaW3g6hQIUGe5lueI13ArYRAhZC0LHKPuVfv5OKeMqxYRtcN3YK6Ddc1t61rsA7MU1cAKzOGsiQ7aNyNBQHOV6z-W4-ws_DnZKYRMz0D_hwbeHO0ZKhciXng5VDCX4hyb47LExmO5N1mfihN3iHEkX_19rIgunfkSb9gd9B_AaazAttBEPPLtbsoZneQXBRl3PWiDpC_yXiLTWAd13AOBYHzBMKeJ4hplUqsAGTaGSztbpvV92wz_YX9kMEucHMu5hoM-TJbuWoheiiiKSFBNRK_g_rqXZo1UZjDOnHpHGJxOnlJBPp94Zvwh8sKLOpOd4qeOMLbnYKiag00al5x_3fBXq-KI0Y31OJfgDdCaKAQ0DUX71HN6XDOlvU1Iwh48iASJHdQGDmjhcS8YoeX9omwPiYhcbGJGzEVrn3H7h24eIf_7bVRpicMhjwghB0xtqTT0eVam1l8kr1-5kem7Dr2Kyqm2HpEwbi3KPXKYDXQRbHElEhazMCYr2wnjx_Bx2ai2uZa8uQyjN1zh1cjWHH0TicL2eAyc6YPKfKpmc5QwLrgT0ddQDhvXkCkN50fOR1Sbl56iFoAL8goFl3QA5wBk51vsDsquEt7nlz6sGTHzknENb-eEayrXnw-Q5FueFwqzoJpUrEYDXTxgOU8XVhrPv0Ot-BO6ORfzn3_1gREcHjhrc6RdF01NNqyzyVG0BdckywvAnzUGskWdCfP62dKdx46lAIRVPd3xG4tViaQ79GAeMVnqSeCLXbOyqfnJwhOT2fgQzLwxcj1tqGBBd3Pfx2d5-10WiL_mis0ven6golqaLq1EQsveb9AJpkYgJxdBeyHZXxNLMh4_XAuK1ZIs9F8Cz1vFEVcAFipev-cFyRvsdcNI2-HK2nOGkypEcuVATyLtA0jKeyPtE4TJ3_l8KXltEZjWycQAd_8Tj9is3wisC8bfzjll8UBjFZp-rzmCr8kA4cZih9gl27TiCmhyKhgMfDUIUmuDL_Rn9DLxEAT3Ebl1SW0ToCciNtKTH9oO-wnkPd-jg1HCooLcg-K_QkOTptJNZRFbXpooKqwH5Z9qsCxurZxnS_MscnE0qTa4EqrlpiDnj4FBs4q9SEPlKequfYzFmjQis1iwsReutf6pHmsvRmz9gx5vd6NMIkI05IeLNDElvlOGD04m1vR4ZISdmdHaAgaW9_AUPGx0vP1Rqe36cvebwUYSnzdbZ7y1s7PH7GXF5r7zNEzY9bHmXvsjb3N_u9BkenwkQfZGS6ez0AAAAAAAAAAALGSAlKzg7Qw";

/// The `kid` of the ML-DSA-87 example of RFC 9964 Appendix A.1, the
/// key's thumbprint (§6).
const ML_DSA_87_KID: &str = "tRn1JNIkgMsABVQBlXeDHxAIcclh-2IX0UdDEzPt5XU";

/// The payload every RFC 9964 Appendix A.1 example signs.
const FRODO: &str = "It\u{2019}s a dangerous business, Frodo, going out your door.";

/// The JWS of RFC 8037 Appendix A.4.
const ED25519_JWS: &str = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";

/// The public key of RFC 8037 Appendix A.2.
const ED25519_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

/// The private key of RFC 8037 Appendix A.1, `d`.
const ED25519_D: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";

/// The JWS of RFC 7515 Appendix A.3.1.
const ES256_JWS: &str = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";

/// Returns the key of an RFC 9964 Appendix A.1 example: the all-zero seed
/// (§4) of `algorithm`'s parameter set.
fn seeded(algorithm: Algorithm) -> PrivateKey {
    PrivateKey::from_ml_dsa_seed(algorithm, &[0; 32]).expect("a 32-octet seed")
}

#[test]
fn the_rfc_9964_examples_verify_with_the_key_their_seed_expands_to() -> Result<(), Box<dyn StdError>>
{
    for (algorithm, token, kid) in [
        (Algorithm::MlDsa44, ML_DSA_44_JWS, ML_DSA_44_KID),
        (Algorithm::MlDsa65, ML_DSA_65_JWS, ML_DSA_65_KID),
        (Algorithm::MlDsa87, ML_DSA_87_JWS, ML_DSA_87_KID),
    ] {
        let public = seeded(algorithm).public_jwk().clone();
        assert_eq!(kid, public.thumbprint(), "RFC 9964 §6: {algorithm}");
        assert_eq!(
            Some(algorithm),
            public.algorithm(),
            "RFC 9964 §3: alg is REQUIRED"
        );
        let jws = decode(token)?;
        assert_eq!(algorithm, jws.header().alg);
        assert_eq!(Some(kid), jws.header().kid.as_deref());
        assert_eq!(FRODO.as_bytes(), jws.verify(&public)?, "{algorithm}");
        let read = Jwk::try_from(&public.to_value())?;
        assert_eq!(public, read, "the AKP JWK reads back as written");
        let mut tampered = token.to_owned();
        tampered.pop();
        tampered.push(if token.ends_with('A') { 'B' } else { 'A' });
        assert!(
            matches!(decode(&tampered)?.verify(&public), Err(JwsError::Signature)),
            "{algorithm}: a changed signature does not verify"
        );
    }
    Ok(())
}

#[test]
fn an_akp_key_with_a_private_member_or_another_parameter_set_is_refused() {
    let public = seeded(Algorithm::MlDsa44).public_jwk().to_value();
    let mut private = public.clone();
    private["priv"] = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    assert_eq!(
        Err(JwkError::Private),
        Jwk::try_from(&private),
        "RFC 9964 §3: priv MUST NOT be present in a public key"
    );
    let mut other_set = public.clone();
    other_set["alg"] = json!("ML-DSA-65");
    assert_eq!(
        Err(JwkError::Length { name: "pub" }),
        Jwk::try_from(&other_set),
        "RFC 9964 §5 and §7.3: pub has the length of its parameter set"
    );
    let mut no_alg = public.clone();
    if let Some(members) = no_alg.as_object_mut() {
        members.remove("alg");
    }
    assert_eq!(
        Err(JwkError::Algorithm),
        Jwk::try_from(&no_alg),
        "RFC 9964 §3"
    );
    let mut classical = public;
    classical["alg"] = json!("ES256");
    assert_eq!(Err(JwkError::Algorithm), Jwk::try_from(&classical));
    assert!(
        matches!(
            PrivateKey::from_ml_dsa_seed(Algorithm::MlDsa65, &[0; 31]),
            Err(KeyError::Seed)
        ),
        "RFC 9964 §7.3: the seed length check"
    );
    assert!(matches!(
        PrivateKey::from_ml_dsa_seed(Algorithm::Es256, &[0; 32]),
        Err(KeyError::Seed)
    ));
}

#[test]
fn the_rfc_8037_example_verifies_and_signs_as_published() -> Result<(), Box<dyn StdError>> {
    let public = Jwk::try_from(&json!({ "kty": "OKP", "crv": "Ed25519", "x": ED25519_X }))?;
    assert_eq!(
        "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k",
        public.thumbprint(),
        "RFC 8037 Appendix A.3"
    );
    assert_eq!(
        b"Example of Ed25519 signing".as_slice(),
        decode(ED25519_JWS)?.verify(&public)?
    );
    // NOTE: RFC 8410 §7, the PKCS#8 document of an Ed25519 private key around its 32 octets.
    let mut pkcs8 = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    pkcs8.extend(URL_SAFE_NO_PAD.decode(ED25519_D)?);
    let key = SigningKey::new(PrivateKey::from_pkcs8(&pkcs8)?, Algorithm::EdDsa)?;
    assert_eq!(&public, key.public_jwk(), "RFC 8037 Appendix A.2");
    let (input, signature) = ED25519_JWS.rsplit_once('.').ok_or("three segments")?;
    assert_eq!(
        signature,
        URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes())?),
        "Ed25519 is deterministic (RFC 8032 §5.1.6)"
    );
    Ok(())
}

#[test]
fn the_rfc_7515_es256_example_verifies() -> Result<(), Box<dyn StdError>> {
    let public = Jwk::try_from(&json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
    }))?;
    let claims = decode(ES256_JWS)?.verify_claims(&public)?;
    assert_eq!(Some(&json!("joe")), claims.get("iss"));
    assert!(
        decode(ES256_JWS)?
            .verify(&public.with_algorithm(Algorithm::Es256)?)
            .is_ok(),
        "a key restricted to ES256 verifies ES256"
    );
    Ok(())
}

#[test]
fn every_algorithm_signs_and_verifies_in_a_round_trip() -> Result<(), Box<dyn StdError>> {
    let keys = [
        rsa_key("rs256", Algorithm::Rs256),
        rsa_key("rs384", Algorithm::Rs384),
        rsa_key("rs512", Algorithm::Rs512),
        rsa_key("ps256", Algorithm::Ps256),
        rsa_key("ps384", Algorithm::Ps384),
        rsa_key("ps512", Algorithm::Ps512),
        ec_key("es256", Algorithm::Es256),
        ec_key("es384", Algorithm::Es384),
        ed_key("eddsa"),
        ml_dsa_key("ml-dsa-44", Algorithm::MlDsa44),
        ml_dsa_key("ml-dsa-65", Algorithm::MlDsa65),
        ml_dsa_key("ml-dsa-87", Algorithm::MlDsa87),
    ];
    let covered: Vec<Algorithm> = keys.iter().map(|key| key.alg).collect();
    assert_eq!(
        Algorithm::all(),
        covered.as_slice(),
        "every algorithm is covered"
    );
    for (index, key) in keys.iter().enumerate() {
        let mut header = Header::new(key.alg);
        header.kid = Some(key.kid.clone());
        let claims = json!({ "iss": "https://as.example.org", "sub": "synthetic" });
        let token = encode(&header, &claims, &key.signing)?;
        let public = Jwk::try_from(&key.jwk)?;
        let jws = decode(&token)?;
        assert_eq!(&header, jws.header(), "{}", key.alg);
        let read = jws.verify_claims(&public)?;
        assert_eq!(claims, serde_json::Value::Object(read), "{}", key.alg);
        let other = &keys[(index + 1) % keys.len()];
        assert!(
            jws.verify(&Jwk::try_from(&other.jwk)?).is_err(),
            "{}: another key verifies nothing",
            key.alg
        );
    }
    Ok(())
}

#[test]
fn none_a_symmetric_algorithm_and_a_critical_extension_are_refused() {
    let encode_json = |value: serde_json::Value| URL_SAFE_NO_PAD.encode(value.to_string());
    let claims = encode_json(json!({ "sub": "synthetic" }));
    for alg in ["none", "HS256", "HS384", "HS512", "es256"] {
        let token = format!("{}.{claims}.", encode_json(json!({ "alg": alg })));
        assert!(
            matches!(decode(&token), Err(JwsError::Algorithm)),
            "RFC 8725 §3.1 and §3.2: {alg}"
        );
    }
    let critical = format!(
        "{}.{claims}.c2ln",
        encode_json(json!({ "alg": "ES256", "crit": ["exp"], "exp": 1 }))
    );
    assert!(
        matches!(decode(&critical), Err(JwsError::Critical)),
        "RFC 7515 §4.1.11"
    );
    let repeated = format!(
        "{}.{claims}.c2ln",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256","alg":"ML-DSA-65"}"#)
    );
    assert!(
        matches!(decode(&repeated), Err(JwsError::Malformed)),
        "RFC 7515 §5.2"
    );
    for malformed in [
        "",
        "a.b",
        "a.b.c.d",
        "e30.e30.c2ln",
        "eyJhbGciOiJFUzI1NiJ9=.e30.c2ln",
    ] {
        assert!(decode(malformed).is_err(), "{malformed:?}");
    }
}

#[test]
fn a_key_verifies_and_signs_its_own_algorithm_alone() -> Result<(), Box<dyn StdError>> {
    let rsa = rsa_key("rsa", Algorithm::Rs256);
    let mut header = Header::new(Algorithm::Ps256);
    header.kid = Some(String::from("rsa"));
    let claims = json!({ "sub": "synthetic" });
    assert!(
        matches!(
            encode(&header, &claims, &rsa.signing),
            Err(JwsError::KeyAlgorithm {
                algorithm: Algorithm::Ps256
            })
        ),
        "the header names the algorithm the key signs with"
    );
    let pss = SigningKey::new(rsa.signing.private_key().clone(), Algorithm::Ps256)?;
    let token = encode(&header, &claims, &pss)?;
    let restricted = Jwk::try_from(&rsa.jwk)?.with_algorithm(Algorithm::Rs256)?;
    assert!(
        matches!(
            decode(&token)?.verify(&restricted),
            Err(JwsError::KeyAlgorithm {
                algorithm: Algorithm::Ps256
            })
        ),
        "RFC 7517 §4.4: a JWK whose alg is RS256 verifies no PS256 token"
    );
    assert!(decode(&token)?.verify(&Jwk::try_from(&rsa.jwk)?).is_ok());
    let ec = ec_key("ec", Algorithm::Es256);
    assert!(
        matches!(
            decode(&token)?.verify(&Jwk::try_from(&ec.jwk)?),
            Err(JwsError::KeyAlgorithm { .. })
        ),
        "RFC 8725 §3.1: an EC key verifies no RSA signature"
    );
    let small = ml_dsa_key("small", Algorithm::MlDsa44);
    let large = ml_dsa_key("large", Algorithm::MlDsa65);
    let mut header = Header::new(Algorithm::MlDsa65);
    header.kid = Some(String::from("small"));
    let token = encode(&header, &claims, &large.signing)?;
    assert!(
        matches!(
            decode(&token)?.verify(&Jwk::try_from(&small.jwk)?),
            Err(JwsError::KeyAlgorithm {
                algorithm: Algorithm::MlDsa65
            })
        ),
        "RFC 9964 §5: an ML-DSA-44 key verifies no ML-DSA-65 signature"
    );
    assert!(
        matches!(
            SigningKey::new(small.signing.private_key().clone(), Algorithm::MlDsa65),
            Err(KeyError::Algorithm {
                algorithm: Algorithm::MlDsa65
            })
        ),
        "an ML-DSA-44 key signs no ML-DSA-65"
    );
    Ok(())
}

#[test]
fn a_key_is_selected_by_kid_or_as_the_one_that_fits() -> Result<(), Box<dyn StdError>> {
    let keys = [
        Jwk::try_from(&ec_key("a", Algorithm::Es256).jwk)?,
        Jwk::try_from(&ec_key("b", Algorithm::Es256).jwk)?,
        Jwk::try_from(&ml_dsa_key("c", Algorithm::MlDsa65).jwk)?,
    ];
    assert_eq!(
        Some("b"),
        select(&keys, Some("b"), Algorithm::Es256).and_then(Jwk::kid)
    );
    assert_eq!(
        None,
        select(&keys, Some("b"), Algorithm::MlDsa65),
        "a kid of another algorithm"
    );
    assert_eq!(
        None,
        select(&keys, None, Algorithm::Es256),
        "two candidates, no kid"
    );
    assert_eq!(
        Some("c"),
        select(&keys, None, Algorithm::MlDsa65).and_then(Jwk::kid)
    );
    assert_eq!(None, select(&keys, None, Algorithm::MlDsa44));
    let encrypting = Jwk::try_from(&json!({
        "kty": "EC", "crv": "P-256", "use": "enc",
        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
    }))?;
    assert!(!encrypting.verifies(Algorithm::Es256), "RFC 7517 §4.2");
    Ok(())
}
