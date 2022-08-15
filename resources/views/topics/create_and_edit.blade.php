@extends('layouts.app')

@section('content')

<div class="container">
  <div class="col-md-10 offset-md-1">
    <div class="card ">

      <div class="card-body">
        <h2 class="">
          <i class="far fa-edit"></i>
          @if($topic->id)
            编辑话题
          @else
            新建话题
          @endif
        </h2>

        <hr>

        @if($topic->id)
          <form action="{{ route('topics.update', $topic->id) }}" method="POST" accept-charset="UTF-8">
          <input type="hidden" name="_method" value="PUT">
        @else
          <form action="{{ route('topics.store') }}" method="POST" accept-charset="UTF-8">
        @endif

          @include('shared._error')

          <input type="hidden" name="_token" value="{{ csrf_token() }}">

          <div class="mb-3">
            <input class="form-control" type="text" name="title" value="{{ old('title', $topic->title ) }}" placeholder="请填写标题" required />
          </div>

          <div class="mb-3">
            <select class="form-control" name="category_id" required>
              <option value="" hidden disabled selected>请选择分类</option>
              @foreach($categories as $value)
                <option value="{{ $value->id }}" {{ $topic->category_id == $value->id ? 'selected' : ''}}>{{ $value->name }}</option>
              @endforeach
            </select>
          </div>

          <div class="mb-3">
            <textarea name="body" class="form-control" id="editor" rows="6" placeholder="请填入至少三个字符的内容">{{ old('body', $topic->body ) }}</textarea>
          </div>

          <div class="well well-sm">
            <button type="submit" class="btn btn-primary">
              <i class="far far-save mr-2" aria-hidden="true"></i> 保存
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
</div>

@endsection

@section('styles')
  <link rel="stylesheet" type="text/css" href="{{ asset('css/simditor.css') }}">
@stop

@section('scripts')
  <script type="text/javascript" src="{{ asset('js/jquery.min.js') }}"></script>
  <script type="text/javascript" src="{{ asset('js/module.js') }}"></script>
  <script type="text/javascript" src="{{ asset('js/hotkeys.js') }}"></script>
  <script type="text/javascript" src="{{ asset('js/uploader.js') }}"></script>
  <script type="text/javascript" src="{{ asset('js/simditor.js') }}"></script>

  <script>
    jQuery(function ($) {
      var editor = new Simditor({
        textarea: $('#editor'),
        upload: {
          url: '{{ route('topics.upload_image') }}',
          params: {
            _token: '{{ csrf_token() }}'
          },
          fileKey: 'upload_file', //服务器端获取图片的键值
          connectionCount: 3, // 最多只能同时上传3张图片
          leaveConfirm: '文件上传中，关闭此页面将取消上传。'
        },
        pasteImage: true, //是否支持图片黏贴上传
      });
    });
  </script>
@stop
