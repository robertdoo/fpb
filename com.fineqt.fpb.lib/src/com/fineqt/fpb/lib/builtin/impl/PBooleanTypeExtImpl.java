/****************************************************************
Fine Packet Builder, copyright (C) 2007-2009 fineqt.com

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, 
but WITHOUT ANY WARRANTY; without even the implied warranty of 
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
GNU General Public License for more details at gnu.org.
******************************************************************/
package com.fineqt.fpb.lib.builtin.impl;

import com.fineqt.fpb.lib.api.util.DecodeException;
import com.fineqt.fpb.lib.api.util.DumpException;
import com.fineqt.fpb.lib.api.util.EncodeException;
import com.fineqt.fpb.lib.api.util.buffer.BitBufferException;
import com.fineqt.fpb.lib.api.util.buffer.BufferTimeoutException;
import com.fineqt.fpb.lib.api.util.buffer.IEnsurableBitBuffer;
import com.fineqt.fpb.lib.api.util.buffer.IReadableBitBuffer;
import com.fineqt.fpb.lib.builtin.PBooleanValue;
import com.fineqt.fpb.lib.codec.DecodeParameters;
import com.fineqt.fpb.lib.codec.DecodeResult;
import com.fineqt.fpb.lib.codec.FlagFieldReader;
import com.fineqt.fpb.lib.codec.FlagFieldWriter;
import com.fineqt.fpb.lib.meta.PModuleExt;
import com.fineqt.fpb.lib.meta.context.DecodeContext;
import com.fineqt.fpb.lib.meta.context.DumpContext;
import com.fineqt.fpb.lib.meta.context.EncodeContext;
import com.fineqt.fpb.lib.meta.exception.MetaException;
import com.fineqt.fpb.lib.model.fpbmodule.ByteOrder;
import com.fineqt.fpb.lib.model.fpbmodule.PBoolean;
import com.fineqt.fpb.lib.model.fpbmodule.PFpbTypeEV;
import com.fineqt.fpb.lib.model.fpbmodule.PType;
import com.fineqt.fpb.lib.type.CreatePTypeValueParamaters;
import com.fineqt.fpb.lib.type.PFpbTypeEVAttrs;
import com.fineqt.fpb.lib.type.impl.PPrimitiveTypeExtBase;
import com.fineqt.fpb.lib.util.SerializeUtil;
import com.fineqt.fpb.lib.value.PTypeElementMeta;
import com.fineqt.fpb.lib.value.PValue;

public class PBooleanTypeExtImpl extends PPrimitiveTypeExtBase {

	public PBooleanTypeExtImpl(PType pmodel, PModuleExt pmoduleExt) {
		super(pmodel, pmoduleExt);
		assert pmodel instanceof PBoolean;
	}

	@Override
	public PValue createNormalValue(CreatePTypeValueParamaters paras) {
		PBooleanValue result = (PBooleanValue)super.createNormalValue(paras);
		if (paras.getInitValue() != null) {
			result.assignPValue(paras.getInitValue());
		}
		return result;
	}
	
	public static class PBooleanEVExt extends PFpbPrimitiveEVExt {
		
		public PBooleanEVExt(PFpbTypeEV model) {
			super(model);
		}

		@Override
		public int doEncode(EncodeContext cxt, PValue value,
				int parentLength, PTypeElementMeta elementMeta,
				ByteOrder byteOrder) throws EncodeException {
			assert value instanceof PBooleanValue;
			PBooleanValue bvalue = (PBooleanValue)value;
			int resultLength = 1;
			//Encode
			if (cxt.withEncodeAction()) {
				FlagFieldWriter writer = cxt.getFlagFieldWriter();
				try {
					if (writer != null) {
						writer.writeBoolean(bvalue.getBoolean());
					} else {
						SerializeUtil.encodeBoolean4fpb(cxt.getBuffer(), bvalue.getBoolean());
					}
				} catch (BitBufferException e) {
					throw new EncodeException(targetTypeMeta, 
							MetaException.CODE.BIT_BUFFER_EXCEPTION_ERROR, e);
				}
			}
			return resultLength;
		}

		@Override
        protected void assumeFixedDecodeLength(DecodeContext cxt,
                IReadableBitBuffer input, PTypeElementMeta elementMeta, 
                DecodeParameters paras, DecodeResult result)
                throws DecodeException {
		    int fixedLength = 1;
		    paras.setHypFixedLength(fixedLength);
            //增量模式处理
		    if (cxt.isIncrement()) {
                IEnsurableBitBuffer eBuffer = (IEnsurableBitBuffer)cxt.getOrgInput();
                try {
                    eBuffer.ensureSpace(input.arrayOffset() + input.position(), 
                            fixedLength);
                } catch (BufferTimeoutException e) {
                    throw new DecodeException(targetTypeMeta,  
                            MetaException.CODE.BIT_BUFFER_EXCEPTION_ERROR, 
                            e);
                }                       
		    }
        }

        @Override
		protected DecodeResult doDecode(DecodeContext cxt, IReadableBitBuffer input, 
		        PTypeElementMeta elementMeta, DecodeParameters paras, DecodeResult result) 
		throws DecodeException {
			//Decode
			boolean value;
			int length = paras.getHypFixedLength();
			//剩余长度不够并且可选
			if (elementMeta.isOptional() && input.remaining() < length) {
				return result;
			//有实际的数据
			} else {
				try {
					FlagFieldReader reader = cxt.getFlagFieldReader();
					if (reader != null) {
						value = reader.readBoolean();
					} else {
						value = SerializeUtil.decodeBoolean4fpb(input);
					}
				} catch (BitBufferException e) {
					throw new DecodeException(targetTypeMeta, 
							MetaException.CODE.BIT_BUFFER_EXCEPTION_ERROR, e);
				}
				PBooleanValue pvalue = (PBooleanValue)targetTypeMeta.createEmptyValue();
				pvalue.setBoolean(value);
				result.setValueLength(length);
				result.setValue(pvalue);
				return result;
			}
		}
		@Override
		protected int doDump(DumpContext cxt, PValue value, String valueName,
		        PTypeElementMeta elementMeta, int deep) 
		throws DumpException {
			int resultLength = 1;
			//dump
			dumpPrimitive(cxt, value, valueName, elementMeta.getConstraints(), deep, 
			        resultLength, (PFpbTypeEVAttrs)elementMeta.getPriorityAttrs());
			return resultLength;
		}
		
	}
}