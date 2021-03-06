using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using Semmle.Util;

namespace Semmle.Extraction.CIL.Entities
{
    internal sealed partial class NoMetadataHandleType : Type
    {
        private readonly string originalName;
        private readonly string name;
        private readonly string? assemblyName;
        private readonly string containerName;
        private readonly bool isContainerNamespace;

        private readonly Lazy<TypeTypeParameter[]>? typeParams;

        // Either null or notEmpty
        private readonly Type[]? thisTypeArguments;
        private readonly Type unboundGenericType;
        private readonly Type? containingType;

        private readonly NamedTypeIdWriter idWriter;

        public NoMetadataHandleType(Context cx, string originalName) : base(cx)
        {
            this.originalName = originalName;
            this.idWriter = new NamedTypeIdWriter(this);

            var nameParser = new FullyQualifiedNameParser(originalName);

            name = nameParser.ShortName;
            assemblyName = nameParser.AssemblyName;
            isContainerNamespace = nameParser.IsContainerNamespace;
            containerName = nameParser.ContainerName;

            unboundGenericType = nameParser.UnboundGenericTypeName == null
                ? this
                : new NoMetadataHandleType(Cx, nameParser.UnboundGenericTypeName);

            if (nameParser.TypeArguments != null)
            {
                thisTypeArguments = nameParser.TypeArguments.Select(t => new NoMetadataHandleType(Cx, t)).ToArray();
            }
            else
            {
                typeParams = new Lazy<TypeTypeParameter[]>(GenericsHelper.MakeTypeParameters(this, ThisTypeParameterCount));
            }

            containingType = isContainerNamespace
                ? null
                : new NoMetadataHandleType(Cx, containerName);

            Populate();
        }

        private void Populate()
        {
            if (isContainerNamespace &&
                !ContainingNamespace!.IsGlobalNamespace)
            {
                Cx.Populate(ContainingNamespace);
            }

            Cx.Populate(this);
        }

        public override bool Equals(object? obj)
        {
            return obj is NoMetadataHandleType t && originalName.Equals(t.originalName, StringComparison.Ordinal);
        }

        public override int GetHashCode()
        {
            return originalName.GetHashCode(StringComparison.Ordinal);
        }

        public override IEnumerable<IExtractionProduct> Contents
        {
            get
            {
                foreach (var tp in typeParams?.Value ?? Array.Empty<TypeTypeParameter>())
                    yield return tp;

                foreach (var c in base.Contents)
                    yield return c;

                var i = 0;
                foreach (var type in ThisTypeArguments)
                {
                    yield return type;
                    yield return Tuples.cil_type_argument(this, i++, type);
                }
            }
        }

        public override CilTypeKind Kind => CilTypeKind.ValueOrRefType;

        public override string Name => GenericsHelper.GetNonGenericName(name);

        public override Namespace? ContainingNamespace => isContainerNamespace
            ? containerName == Cx.GlobalNamespace.Name
                ? Cx.GlobalNamespace
                : new Namespace(Cx, containerName)
            : null;

        public override Type? ContainingType => containingType;

        public override Type SourceDeclaration => unboundGenericType;

        public override Type Construct(IEnumerable<Type> typeArguments)
        {
            if (TotalTypeParametersCount != typeArguments.Count())
                throw new InternalError("Mismatched type arguments");

            return Cx.Populate(new ConstructedType(Cx, this, typeArguments));
        }

        public override void WriteAssemblyPrefix(TextWriter trapFile)
        {
            if (!string.IsNullOrWhiteSpace(assemblyName))
            {
                var an = new AssemblyName(assemblyName);
                trapFile.Write(an.Name);
                trapFile.Write('_');
                trapFile.Write((an.Version ?? new Version(0, 0, 0, 0)).ToString());
                trapFile.Write(Type.AssemblyTypeNameSeparator);
            }
            else
            {
                Cx.WriteAssemblyPrefix(trapFile);
            }
        }

        public override void WriteId(TextWriter trapFile, bool inContext)
        {
            idWriter.WriteId(trapFile, inContext);
        }

        public override int ThisTypeParameterCount => unboundGenericType == this
            ? GenericsHelper.GetGenericTypeParameterCount(name)
            : thisTypeArguments!.Length;

        public override IEnumerable<Type> TypeParameters => unboundGenericType == this
            ? GenericsHelper.GetAllTypeParameters(containingType, typeParams!.Value)
            : GenericArguments;

        public override IEnumerable<Type> ThisTypeArguments => unboundGenericType == this
            ? base.ThisTypeArguments
            : thisTypeArguments!;

        public override IEnumerable<Type> ThisGenericArguments => unboundGenericType == this
            ? typeParams!.Value
            : thisTypeArguments!;
    }
}
